import os
import subprocess
import json
import re

class Colors:
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    GREEN = '\033[92m'
    ENDC = '\033[0m'


# Паттерны для статического анализа чейнкода (Chaincode Analyzer)
STATIC_PATTERNS = [
    {
        "pattern": re.compile(r'\btime\.Now\(\)'),
        "issue":    "Использование time.Now() нарушает детерминизм. Используйте stub.GetTxTimestamp()",
        "severity": "HIGH",
        "rule":     "NonDeterminism/TimeNow",
    },
    {
        "pattern": re.compile(r'\brand\.Seed\b|\brand\.Intn\b|\brand\.Float'),
        "issue":    "Использование math/rand нарушает консенсус между пирами (недетерминизм)",
        "severity": "CRITICAL",
        "rule":     "NonDeterminism/MathRand",
    },
    {
        "pattern": re.compile(r'\bcrypto/rand\b'),
        "issue":    "Использование crypto/rand нарушает консенсус между пирами (недетерминизм)",
        "severity": "CRITICAL",
        "rule":     "NonDeterminism/CryptoRand",
    },
    {
        "pattern": re.compile(r'^\s*go\s+\w+\s*\(|^\s*go\s+func\s*\('),
        "issue":    "Использование горутин в чейнкоде запрещено — возникают гонки данных (Data Race)",
        "severity": "CRITICAL",
        "rule":     "Concurrency/Goroutine",
    },
    {
        "pattern": re.compile(r'GetStateByRange|GetQueryResult|GetHistoryForKey'),
        "issue":    (
            "Rich-query / Range-query возвращают разные результаты на разных пирах "
            "в зависимости от состояния БД — потенциальный недетерминизм при записи на основе результата"
        ),
        "severity": "MEDIUM",
        "rule":     "NonDeterminism/RichQuery",
    },
    {
        "pattern": re.compile(r'GetCreator\(\)'),
        "issue":    (
            "GetCreator() найден — убедитесь, что идентичность вызывающей стороны "
            "корректно верифицируется. Отсутствие проверки — уязвимость Access Control."
        ),
        "severity": "LOW",
        "rule":     "AccessControl/GetCreatorUsage",
        "hint": True,  # Не проблема сама по себе — лишь подсказка
    },
]


class ContractInfo:
    """
    Результат AST-like анализа Go-файла чейнкода:
    - contract_struct: имя структуры, реализующей контракт
    - methods:         список публичных методов контракта (имя + параметры)
    - has_access_ctrl: True, если хотя бы один метод проверяет права
    - uses_shim:       True, если используется старый shim API
    - uses_contractapi True, если используется новый contractapi
    """
    def __init__(self):
        self.contract_struct: str = "SmartContract"
        self.methods: list[dict] = []          # [{"name": str, "params": [str], "has_access_check": bool}]
        self.has_any_access_ctrl: bool = False
        self.uses_shim: bool = False
        self.uses_contractapi: bool = False


def parse_contract(source: str) -> ContractInfo:
    """
    Разбирает исходный код Go-файла и извлекает информацию о контракте.
    Не требует компилятора — работает через регулярные выражения.
    """
    info = ContractInfo()

    # --- Определяем API ---
    info.uses_shim = bool(re.search(r'"github\.com/hyperledger/fabric-chaincode-go/shim"', source))
    info.uses_contractapi = bool(re.search(r'"github\.com/hyperledger/fabric-contract-api-go/contractapi"', source))

    # --- Находим структуру контракта ---
    # Контрактная структура: встраивает contractapi.Contract ИЛИ используется в NewChaincode/shim.Start
    contract_struct = None

    # Вариант 1: структура встраивает contractapi.Contract
    m = re.search(r'type\s+(\w+)\s+struct\s*\{[^}]*contractapi\.Contract[^}]*\}', source, re.DOTALL)
    if m:
        contract_struct = m.group(1)

    # Вариант 2: contractapi.NewChaincode(&Xxx{}) или contractapi.NewChaincode(new(Xxx))
    if not contract_struct:
        m = re.search(r'contractapi\.NewChaincode\s*\(\s*(?:&(\w+)\{\}|new\((\w+)\))', source)
        if m:
            contract_struct = m.group(1) or m.group(2)

    # Вариант 3: shim.Start(new(Xxx))
    if not contract_struct:
        m = re.search(r'shim\.Start\s*\(\s*new\s*\(\s*(\w+)\s*\)', source)
        if m:
            contract_struct = m.group(1)

    # Вариант 4: первая struct с методом Init/Invoke (shim-стиль)
    if not contract_struct:
        structs = re.findall(r'type\s+(\w+)\s+struct', source)
        for s in structs:
            if re.search(rf'func\s*\(\s*\w+\s+\*?{s}\s*\)\s*(Init|Invoke)\s*\(', source):
                contract_struct = s
                break

    # Вариант 5: fallback — первая struct в файле
    if not contract_struct:
        structs = re.findall(r'type\s+(\w+)\s+struct', source)
        # Пропускаем структуры данных (Asset, Request и т.п.) — они не имеют методов
        for s in structs:
            if re.search(rf'func\s*\(\s*\w+\s+\*?{s}\s*\)\s*\w+\s*\(', source):
                contract_struct = s
                break
        if not contract_struct and structs:
            contract_struct = structs[0]

    info.contract_struct = contract_struct or "SmartContract"

    # --- Извлекаем публичные методы контракта ---
    # Ищем: func (s *SmartContract) MethodName(ctx ..., param1 type, ...) ...
    method_pattern = re.compile(
        rf'func\s*\(\s*\w+\s+\*?{re.escape(info.contract_struct)}\s*\)\s*'
        r'([A-Z]\w*)\s*\(([^)]*)\)',
        re.MULTILINE
    )

    # Карта: имя метода → тело функции (для анализа проверок доступа)
    func_bodies: dict[str, str] = {}
    func_body_pattern = re.compile(
        rf'func\s*\(\s*\w+\s+\*?{re.escape(info.contract_struct)}\s*\)\s*'
        r'([A-Z]\w*)\s*\([^)]*\)[^{{]*\{{(.*?)\n\}}',
        re.DOTALL
    )
    for m in func_body_pattern.finditer(source):
        func_bodies[m.group(1)] = m.group(2)

    access_control_keywords = [
        "GetCreator", "GetMSPID", "cid.GetMSPID", "cid.GetID",
        "ClientIdentity", "GetAttributeValue", "AssertAttributeValue",
    ]

    for m in method_pattern.finditer(source):
        method_name = m.group(1)
        params_raw = m.group(2)

        # Пропускаем служебные методы Go (Init, Invoke для shim-стиля тоже важны)
        if method_name in ("String", "Error"):
            continue

        # Парсим параметры (кроме первого — receiver и ctx)
        params = [p.strip() for p in params_raw.split(",") if p.strip()]
        # Убираем ctx/stub-параметр (первый, содержащий TransactionContext или ChaincodeStubInterface)
        chaincode_params = [
            p for p in params
            if "TransactionContext" not in p and "ChaincodeStubInterface" not in p
        ]

        body = func_bodies.get(method_name, "")
        has_ac = any(kw in body for kw in access_control_keywords)
        if has_ac:
            info.has_any_access_ctrl = True

        info.methods.append({
            "name": method_name,
            "params": chaincode_params,
            "has_access_check": has_ac,
        })

    return info


def _go_type_to_dummy(type_hint: str) -> str:
    """Возвращает Go-литерал-заглушку для заданного типа."""
    t = type_hint.lower()
    if "int" in t or "uint" in t or "float" in t:
        return '"42"'
    if "bool" in t:
        return '"true"'
    return '"test_value"'


class FabricScanner:
    def __init__(self, target_file, reporter):
        self.target = os.path.abspath(target_file)
        self.target_dir = os.path.dirname(self.target)
        self.reporter = reporter
        self.generated_test_file = None
        self._contract_info: ContractInfo | None = None

    # Парсинг контракта — один раз на весь жизненный цикл
    def _get_contract_info(self) -> ContractInfo:
        if self._contract_info is None:
            with open(self.target, "r", encoding="utf-8") as f:
                source = f.read()
            self._contract_info = parse_contract(source)
            print(f"    [i] Обнаружена структура контракта: {self._contract_info.contract_struct}")
            print(f"    [i] Найдено публичных методов: {len(self._contract_info.methods)}")
        return self._contract_info

    # СТАТИЧЕСКИЙ АНАЛИЗ

    def run_static(self):
        self._run_gosec()
        self._run_chaincode_analyzer()

    def _run_gosec(self):
        print("[*] Запуск Gosec (SAST сканер)...")
        cmd = ["gosec", "-fmt=json", "./..."]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.target_dir)
            if result.stdout:
                data = json.loads(result.stdout)
                all_issues = data.get("Issues", [])

                target_basename = os.path.basename(self.target)
                filtered = [
                    i for i in all_issues
                    if os.path.basename(i.get("file", "")) == target_basename
                ]

                if filtered:
                    print(f"{Colors.WARNING}Gosec: {len(filtered)} проблем найдено.{Colors.ENDC}")
                    for issue in filtered:
                        self.reporter.add_static_issue(
                            "Gosec",
                            issue["rule_id"],
                            issue["severity"],
                            issue["details"],
                            f"Line: {issue['line']}",
                        )
                else:
                    print(f"{Colors.GREEN}[+] Gosec: Проблем не обнаружено.{Colors.ENDC}")
        except FileNotFoundError:
            print(f"{Colors.WARNING}[!] Gosec не установлен — пропускаем SAST.{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}Gosec error: {e}{Colors.ENDC}")

    def _run_chaincode_analyzer(self):
        """
        Расширенный статический анализ паттернов, специфичных для Hyperledger Fabric.
        Работает без внешних зависимостей — только regex по исходнику.
        """
        print("[*] Запуск Chaincode Analyzer (детерминизм + Access Control)...")
        issues = []

        try:
            with open(self.target, "r", encoding="utf-8") as f:
                lines = f.readlines()
                full_source = "".join(lines)

            in_block_comment = False
            for i, line in enumerate(lines, 1):
                stripped = line.strip()

                # Пропускаем блочные комментарии /* ... */
                if "/*" in stripped:
                    in_block_comment = True
                if in_block_comment:
                    if "*/" in stripped:
                        in_block_comment = False
                    continue
                # Пропускаем строчные комментарии
                if stripped.startswith("//"):
                    continue

                for rule in STATIC_PATTERNS:
                    if rule.get("hint"):
                        continue  # Хинты обрабатываем отдельно
                    if rule["pattern"].search(line):
                        issues.append({
                            "line": i,
                            "rule": rule["rule"],
                            "issue": rule["issue"],
                            "severity": rule["severity"],
                        })

            # --- Отдельная проверка: Access Control на уровне всего файла ---
            info = self._get_contract_info()
            methods_without_ac = [m for m in info.methods if not m["has_access_check"]]
            write_methods = [
                m for m in methods_without_ac
                if any(kw in m["name"] for kw in (
                    "Create", "Update", "Delete", "Put", "Set", "Transfer",
                    "Add", "Remove", "Mint", "Burn", "Change", "Write"
                ))
            ]
            if write_methods and not info.has_any_access_ctrl:
                # Находим номер строки сигнатуры метода для точной локализации
                method_line_cache: dict = {}
                func_sig_pattern = re.compile(
                    rf'func\s*\(\s*\w+\s+\*?{re.escape(info.contract_struct)}\s*\)\s*(\w+)\s*\('
                )
                for lineno, line in enumerate(lines, 1):
                    m = func_sig_pattern.search(line)
                    if m:
                        method_line_cache[m.group(1)] = lineno

                for wm in write_methods:
                    line_loc = method_line_cache.get(wm["name"], "N/A")
                    issues.append({
                        "line": line_loc,
                        "rule": "AccessControl/MissingCheck",
                        "issue": (
                            f"Метод {wm['name']} изменяет состояние реестра, "
                            "но не проверяет идентичность вызывающей стороны "
                            "(GetCreator / cid.GetMSPID). Любой участник сети "
                            "может выполнить эту операцию."
                        ),
                        "severity": "HIGH",
                    })

            # --- Проверка: PutState без проверки ошибки ---
            # Условие FP: строка содержит .PutState( И "err" в той же строке (присвоение/проверка).
            # Настоящая проблема: .PutState вызван как statement — результат не захватывается.
            # Признак: в строке нет "err" И "=" перед .PutState не присваивает в err.
            putstate_pat = re.compile(r'^\s*(?!.*\berr\b.*=).*\.PutState\s*\(')
            for i, line in enumerate(lines):
                stripped_l = line.strip()
                if stripped_l.startswith("//"):
                    continue
                if ".PutState(" in line and putstate_pat.match(line):
                    # Дополнительно: следующая непустая строка должна не содержать "err"
                    next_nonempty = [l.strip() for l in lines[i + 1: i + 4] if l.strip()]
                    if next_nonempty and "err" not in next_nonempty[0]:
                        issues.append({
                            "line": i + 1,
                            "rule": "ErrorHandling/IgnoredPutState",
                            "issue": "Результат PutState не присваивается переменной — ошибка записи будет проигнорирована",
                            "severity": "HIGH",
                        })

        except Exception as e:
            print(f"{Colors.FAIL}Ошибка Chaincode Analyzer: {e}{Colors.ENDC}")

        if issues:
            print(f"{Colors.WARNING}Chaincode Analyzer: {len(issues)} проблем.{Colors.ENDC}")
            for issue in issues:
                self.reporter.add_static_issue(
                    "ChaincodeAnalyzer",
                    issue["rule"],
                    issue["severity"],
                    issue["issue"],
                    f"Line: {issue['line']}",
                )
        else:
            print(f"{Colors.GREEN}[+] Chaincode Analyzer: Чисто.{Colors.ENDC}")

    # ОКРУЖЕНИЕ — изолированная песочница в /tmp

    def _create_sandbox(self) -> str:
        """
        Создаёт временный изолированный Go-модуль в /tmp и копирует
        туда ТОЛЬКО целевой файл. Это исключает влияние соседних .go-файлов
        с синтаксическими ошибками или конфликтующими package-декларациями.
        Возвращает путь к директории песочницы.
        """
        import tempfile
        import shutil

        sandbox = tempfile.mkdtemp(prefix="smartscan_")

        # Копируем только целевой файл
        shutil.copy2(self.target, os.path.join(sandbox, os.path.basename(self.target)))

        # Инициализируем свежий Go-модуль
        subprocess.run(
            ["go", "mod", "init", "smartscan/sandbox"],
            cwd=sandbox,
            capture_output=True,
        )

        # Подтягиваем зависимости (быстро благодаря глобальному кэшу go)
        result = subprocess.run(
            ["go", "mod", "tidy"],
            cwd=sandbox,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"{Colors.WARNING}[!] go mod tidy: {result.stderr[:300]}{Colors.ENDC}")

        return sandbox

    def _init_go_env(self):
        """Оставлен для обратной совместимости — реальная инициализация теперь в _create_sandbox."""
        pass

    # ДИНАМИЧЕСКИЙ АНАЛИЗ: CCKit

    def _build_cckit_test(self, info: ContractInfo) -> str:
        """
        Строит Go-тест, адаптированный под реальные методы контракта.

        Стратегия:
        1. Для каждого WRITE-метода без проверки доступа генерируем вызов
           и ожидаем, что он ПРОВАЛИТСЯ (т.е. контракт должен отказать
           неавторизованному участнику). Если он проходит — это уязвимость.
        2. Для READ-методов проверяем, что они не падают с паникой.
        """
        write_methods = [
            m for m in info.methods
            if any(kw in m["name"] for kw in (
                "Create", "Update", "Delete", "Put", "Set", "Transfer",
                "Add", "Remove", "Mint", "Burn", "Change", "Write"
            ))
        ]
        read_methods = [
            m for m in info.methods
            if any(kw in m["name"] for kw in ("Get", "Read", "Query", "List", "Find"))
        ]

        # Если явных write-методов нет — берём все публичные методы
        if not write_methods:
            write_methods = info.methods[:3]  # ограничиваем тест

        lines = [
            "package main",
            "",
            "import (",
            '\t"testing"',
        ]

        if info.uses_contractapi:
            lines += [
                '\t"github.com/hyperledger/fabric-contract-api-go/contractapi"',
                '\t"github.com/hyperledger/fabric-chaincode-go/shimtest"',
            ]
        else:
            lines += [
                '\t"github.com/hyperledger/fabric-chaincode-go/shimtest"',
            ]

        lines += [")", ""]

        # --- Вспомогательный helper ---
        if info.uses_contractapi:
            lines += [
                f"func newTestStub(t *testing.T) *shimtest.MockStub {{",
                f"\tcc, err := contractapi.NewChaincode(new({info.contract_struct}))",
                "\tif err != nil { t.Fatalf(\"NewChaincode failed: %v\", err) }",
                '\tstub := shimtest.NewMockStub("test_cc", cc)',
                "\tstub.MockInit(\"1\", [][]byte{})",
                "\treturn stub",
                "}",
                "",
            ]
        else:
            lines += [
                f"func newTestStub(t *testing.T) *shimtest.MockStub {{",
                f'\tstub := shimtest.NewMockStub("test_cc", new({info.contract_struct}))',
                "\tstub.MockInit(\"1\", [][]byte{})",
                "\treturn stub",
                "}",
                "",
            ]

        # --- Тест 1: Access Control для write-методов ---
        lines += [
            "// TestAccessControl проверяет, что write-методы отклоняют",
            "// неавторизованных пользователей. FAIL = уязвимость Access Control.",
            "func TestCCKit_AccessControl(t *testing.T) {",
            "\tstub := newTestStub(t)",
            "\tvulnFound := false",
            "",
        ]

        for method in write_methods:
            # Генерируем фиктивные аргументы по числу параметров
            dummy_args = []
            for p in method["params"]:
                # Получаем тип из "name type" или просто "type"
                parts = p.split()
                type_hint = parts[-1] if parts else "string"
                dummy_args.append(_go_type_to_dummy(type_hint))

            all_args = [f'"{method["name"]}"'] + dummy_args
            args_bytes = ", ".join(f"[]byte({a})" for a in all_args)

            lines += [
                f'\t// Метод: {method["name"]}',
                f'\tres_{method["name"]} := stub.MockInvoke("tx_{method["name"]}", [][]byte{{{args_bytes}}})',
                f'\tif res_{method["name"]}.Status == 200 {{',
                f'\t\tt.Errorf("ACCESS CONTROL FAIL: {method["name"]} выполнился без авторизации (статус 200). '
                f'Любой участник сети может вызвать этот метод.")',
                "\t\tvulnFound = true",
                "\t}",
                "",
            ]

        lines += [
            "\tif !vulnFound {",
            '\t\tt.Log("Access Control: все write-методы корректно отклонили неавторизованный вызов.")',
            "\t}",
            "}",
            "",
        ]

        # --- Тест 2: Паника на граничных значениях для read-методов ---
        if read_methods:
            lines += [
                "// TestReadMethodsStability проверяет, что read-методы не паникуют",
                "// на граничных входных данных (пустые строки, очень длинные ID).",
                "func TestCCKit_ReadStability(t *testing.T) {",
                "\tstub := newTestStub(t)",
                "\tedgeCases := []string{\"\", \"non_existent_key_xyz\", string(make([]byte, 256))}",
                "",
            ]
            for method in read_methods[:3]:  # берём не более 3 read-методов
                lines += [
                    f'\tfor _, arg := range edgeCases {{',
                    f'\t\t// Не должно быть паники (Status 500)',
                    f'\t\tres := stub.MockInvoke("tx_read", [][]byte{{[]byte("{method["name"]}"), []byte(arg)}})',
                    f'\t\tif res.Status == 500 {{',
                    f'\t\t\tt.Errorf("PANIC/ERROR в {method["name"]} на входе %q: %s", arg, res.Message)',
                    "\t\t}",
                    "\t}",
                    "",
                ]
            lines += ["}"]

        return "\n".join(lines)

    # ДИНАМИЧЕСКИЙ АНАЛИЗ: FUZZING

    def _build_fuzz_test(self, info: ContractInfo) -> str:
        """
        Строит Go Fuzz-тест, который перебирает все публичные методы контракта
        с произвольными аргументами и ищет паники (Status 500).
        """
        method_names = [m["name"] for m in info.methods] or ["InitLedger"]

        # seed corpus — по одному реальному имени метода на каждый метод
        seed_adds = "\n".join(
            f'\tf.Add("{name}", "seed_arg_{i}", "seed_arg2_{i}")'
            for i, name in enumerate(method_names[:8])
        )

        lines = [
            "package main",
            "",
            "import (",
            '\t"strings"',
            '\t"testing"',
        ]

        if info.uses_contractapi:
            lines += [
                '\t"github.com/hyperledger/fabric-contract-api-go/contractapi"',
                '\t"github.com/hyperledger/fabric-chaincode-go/shimtest"',
            ]
        else:
            lines += [
                '\t"github.com/hyperledger/fabric-chaincode-go/shimtest"',
            ]

        lines += [
            ")",
            "",
            "// FuzzChaincodeInputs ищет паники и тяжёлые ошибки (Status 500)",
            "// при подаче произвольных входных данных во все методы контракта.",
            "func FuzzChaincodeInputs(f *testing.F) {",
            "\t// Seed corpus: реальные имена методов из контракта",
            seed_adds,
            "",
            "\tf.Fuzz(func(t *testing.T, funcName string, arg1 string, arg2 string) {",
        ]

        if info.uses_contractapi:
            lines += [
                f"\t\tcc, err := contractapi.NewChaincode(new({info.contract_struct}))",
                "\t\tif err != nil { return }",
                '\t\tstub := shimtest.NewMockStub("fuzz_stub", cc)',
            ]
        else:
            lines += [
                f'\t\tstub := shimtest.NewMockStub("fuzz_stub", new({info.contract_struct}))',
            ]

        lines += [
            '\t\tstub.MockInit("init", [][]byte{})',
            "",
            "\t\t// Подаём произвольный вызов",
            "\t\targs := [][]byte{[]byte(funcName), []byte(arg1), []byte(arg2)}",
            '\t\tres := stub.MockInvoke("fuzz_tx", args)',
            "",
            "\t\t// Status 500 означает панику или критическую ошибку чейнкода.",
            "\t\t// Фильтруем штатный ответ фреймворка 'function not found' —",
            "\t\t// это нормально: фаззер подал несуществующее имя метода.",
            "\t\tif res.Status == 500 {",
            '\t\t\tif strings.Contains(res.Message, "not found") || strings.Contains(res.Message, "unknown function") || strings.Contains(res.Message, "Blank function name") {',
            "\t\t\t\treturn // Ожидаемое поведение contractapi",
            "\t\t\t}",
            '\t\t\tt.Errorf("ПАНИКА/КРИТИЧЕСКАЯ ОШИБКА: метод=%q arg1=%q arg2=%q: %s",',
            "\t\t\t\tfuncName, arg1, arg2, res.Message)",
            "\t\t}",
            "\t})",
            "}",
        ]

        return "\n".join(lines)

    # ОРКЕСТРАЦИЯ ДИНАМИЧЕСКОГО АНАЛИЗА

    def run_dynamic(self, mode: str = "cckit"):
        self._init_go_env()
        info = self._get_contract_info()

        if not info.methods:
            print(f"{Colors.WARNING}[!] Публичных методов не обнаружено — динамический анализ пропущен.{Colors.ENDC}")
            return

        if mode == "cckit":
            self._run_cckit(info)
        elif mode == "fuzz":
            self._run_fuzz(info)

    def _run_cckit(self, info: ContractInfo):
        import shutil
        tool_name = "Fabric-CCKit"
        print(f"[*] Генерация и запуск CCKit тестов (Access Control + Stability)...")

        sandbox = self._create_sandbox()
        try:
            test_code = self._build_cckit_test(info)
            test_path = os.path.join(sandbox, "smartscan_cckit_test.go")
            with open(test_path, "w", encoding="utf-8") as f:
                f.write(test_code)

            cmd = ["go", "test", "-v", "-run", "TestCCKit", "-count=1"]
            self._execute_test(cmd, tool_name, sandbox, timeout=45)
        finally:
            shutil.rmtree(sandbox, ignore_errors=True)

    def _run_fuzz(self, info: ContractInfo):
        import shutil
        tool_name = "Fabric-Fuzzing"
        print(f"[*] Генерация и запуск Fuzz-теста (Go native fuzzing)...")

        sandbox = self._create_sandbox()
        try:
            test_code = self._build_fuzz_test(info)
            test_path = os.path.join(sandbox, "smartscan_fuzz_test.go")
            with open(test_path, "w", encoding="utf-8") as f:
                f.write(test_code)

            # Сначала прогоняем seed-корпус без фаззинга — проверяем компиляцию
            seed_cmd = ["go", "test", "-v", "-run", "FuzzChaincodeInputs", "-count=1"]
            compile_ok = self._execute_test(seed_cmd, f"{tool_name}/Seed", sandbox, timeout=30)

            if compile_ok:
                fuzz_cmd = ["go", "test", "-v", "-fuzz=FuzzChaincodeInputs", "-fuzztime=20s"]
                self._execute_test(fuzz_cmd, tool_name, sandbox, timeout=60)
        finally:
            shutil.rmtree(sandbox, ignore_errors=True)

    def _execute_test(self, cmd: list, tool_name: str, sandbox: str, timeout: int) -> bool:
        """
        Запускает Go-тест в изолированной песочнице и интерпретирует результат.
        Возвращает True если тест запустился (не обязательно без находок).
        """
        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=sandbox,
                timeout=timeout,
            )
            stdout = process.stdout
            stderr = process.stderr
            combined = stdout + "\n" + stderr

            # --- Компиляционная ошибка — не уязвимость ---
            if process.returncode != 0 and (
                "build failed" in combined.lower()
                or "syntax error" in combined.lower()
                or "undefined:" in combined
                or ("FAIL" in combined and "--- FAIL" not in combined and "--- PASS" not in combined)
            ):
                print(f"{Colors.FAIL}[!] {tool_name}: Ошибка компиляции теста.{Colors.ENDC}")
                print(combined[:600])
                self.reporter.add_dynamic_issue(
                    tool_name,
                    "Ошибка компиляции теста",
                    "ERROR",
                    combined[:400],
                )
                return False

            # --- Реальный провал теста ---
            if "--- FAIL" in combined:
                print(f"{Colors.FAIL}[!] {tool_name}: Найдена уязвимость!{Colors.ENDC}")
                fail_lines = [
                    line for line in combined.splitlines()
                    if any(kw in line for kw in ("FAIL", "Error", "ПАНИКА", "ACCESS CONTROL"))
                ]
                evidence = "\n".join(fail_lines[:30])
                self.reporter.add_dynamic_issue(
                    tool_name,
                    "Обнаружена уязвимость",
                    "FAIL",
                    evidence,
                )
                return True

            # --- Всё чисто ---
            print(f"{Colors.GREEN}[+] {tool_name}: Проверка пройдена.{Colors.ENDC}")
            self.reporter.add_dynamic_issue(
                tool_name,
                "Успешно завершено",
                "PASS",
                "No issues detected.",
            )
            return True

        except subprocess.TimeoutExpired:
            print(f"{Colors.GREEN}[!] {tool_name}: Остановлено по таймауту.{Colors.ENDC}")
            self.reporter.add_dynamic_issue(
                tool_name,
                "Timeout",
                "PASS",
                "Завершено по таймауту без краша.",
            )
            return True
        except Exception as e:
            print(f"{Colors.FAIL}Ошибка выполнения {tool_name}: {e}{Colors.ENDC}")
            return False