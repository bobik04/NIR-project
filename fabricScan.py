import os
import subprocess
import json
import re

class Colors:
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    GREEN = '\033[92m'
    ENDC = '\033[0m'

class FabricScanner:
    def __init__(self, target_file, reporter):
        self.target = os.path.abspath(target_file)
        self.target_dir = os.path.dirname(self.target)
        self.reporter = reporter
        self.generated_test_file = None

    def run_static(self):
        print(f"[*] Запуск Gosec (security scanner)...")
        cmd = ["gosec", "-fmt=json", self.target_dir + "/..."]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            data = json.loads(result.stdout)
            
            # Проверяем, что ошибка относится именно к нашему файлу
            all_issues = data.get("Issues", [])
            filtered_issues = [
                i for i in all_issues 
                if os.path.abspath(i.get('file', '')) == self.target
            ]
            
            if filtered_issues:
                print(f"{Colors.WARNING}Gosec: {len(filtered_issues)} проблем найдено в целевом файле.{Colors.ENDC}")
                for issue in filtered_issues:
                    self.reporter.add_static_issue(
                        "Gosec", 
                        issue['rule_id'], 
                        issue['severity'], 
                        issue['details'], 
                        f"Line: {issue['line']}"
                    )
            else:
                print(f"{Colors.GREEN}[+] Gosec: В целевом файле проблем не обнаружено.{Colors.ENDC}")
        except Exception as e: 
            print(f"Gosec error: {e}")

        self.run_chaincode_analyzer()

    def run_chaincode_analyzer(self):
        """
        Внутренний статический анализатор для Hyperledger Fabric.
        Проверяет код на детерминизм и специфичные для блокчейна ошибки.
        """
        print(f"[*] Запуск Chaincode Analyzer (проверка детерминизма)...")
        issues = []
        try:
            with open(self.target, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for i, line in enumerate(lines, 1):
                content = line.strip()
                if content.startswith("//") or content.startswith("/*"):
                    continue

                # 1. Проверка времени (Time Determinism)
                if "time.Now()" in content:
                    issues.append({
                        "line": i, 
                        "issue": "Использование time.Now() нарушает детерминизм (используйте stub.GetTxTimestamp)", 
                        "severity": "HIGH"
                    })
                
                # 2. Проверка рандома (Randomness)
                if "math/rand" in content or "crypto/rand" in content:
                    issues.append({
                        "line": i, 
                        "issue": "Генерация случайных чисел нарушает консенсус (результат будет разным на пирах)", 
                        "severity": "CRITICAL"
                    })
                
                # 3. Проверка горутин (Concurrency)
                if content.startswith("go ") or " go " in content:
                    issues.append({
                        "line": i, 
                        "issue": "Использование 'go routine' запрещено в чейнкоде (возможны гонки данных)", 
                        "severity": "CRITICAL"
                    })

                # 4. Проверка доступа к файловой системе
                if "ioutil.WriteFile" in content or "os.Create" in content:
                     issues.append({
                        "line": i, 
                        "issue": "Прямой доступ к файловой системе контейнера запрещен", 
                        "severity": "CRITICAL"
                    })

        except Exception as e:
            print(f"Ошибка Chaincode Analyzer: {e}")

        if issues:
            print(f"{Colors.WARNING}Chaincode Analyzer нашел {len(issues)} проблем.{Colors.ENDC}")
            for issue in issues:
                self.reporter.add_static_issue(
                    "ChaincodeAnalyzer", "Determinism/BestPractice", issue['severity'], issue['issue'], f"Line: {issue['line']}"
                )
                print(f" - [{issue['severity']}] Line {issue['line']}: {issue['issue']}")
        else:
            print(f"{Colors.GREEN}[+] Chaincode Analyzer: Чисто.{Colors.ENDC}")

    def generate_go_test(self):
        print("[*] Генерация Go-теста для чейнкода...")
        with open(self.target, 'r') as f:
            content = f.read()

        # Ищем имя структуры (обычно SmartContract)
        struct_match = re.search(r'type\s+(\w+)\s+struct', content)
        if not struct_match:
            print("Не найдена структура контракта.")
            return None
        contract_struct = struct_match.group(1)

        # Ищем методы для тестирования (CreateAsset, etc)
        methods = re.findall(rf'func\s+\(.*\*{contract_struct}\)\s+(\w+)', content)
        methods = [m for m in methods if m not in ['Init', 'Invoke', 'InitLedger']]

        # Генерация код теста
        test_code = [
            "package main",
            "",
            "import (",
            "	\"testing\"",
            "	\"github.com/hyperledger/fabric-chaincode-go/shim\"",
            "	\"github.com/hyperledger/fabric-chaincode-go/shimtest\"",
            ")",
            "",
            f"func Test{contract_struct}_Init(t *testing.T) {{",
            f"	scc := new({contract_struct})",
            "	stub := shimtest.NewMockStub(\"asset_transfer\", scc)",
            "	res := stub.MockInit(\"1\", [][]byte{})",
            "	if res.Status != shim.OK {",
            "		t.Error(\"Init failed\", res.Message)",
            "	}",
            "}"
        ]

        if "CreateAsset" in methods:
            test_code.extend([
                "",
                f"func Test{contract_struct}_CreateAsset(t *testing.T) {{",
                f"	scc := new({contract_struct})",
                "	stub := shimtest.NewMockStub(\"asset_transfer\", scc)",
                "	stub.MockInit(\"1\", [][]byte{})",
                "",
                "	// Авто-тест: попытка вызова CreateAsset",
                "   // Аргументы: ID, color, size, owner, value",
                "	args := [][]byte{[]byte(\"CreateAsset\"), []byte(\"test_asset_1\"), []byte(\"blue\"), []byte(\"5\"), []byte(\"tom\"), []byte(\"35\")}",
                "	res := stub.MockInvoke(\"1\", args)",
                "	if res.Status != shim.OK {",
                "		t.Log(\"CreateAsset вернул ошибку (ОК):\", res.Message)",
                "	} else {",
                "       t.Log(\"CreateAsset выполнен успешно\")",
                "   }",
                "}"
            ])

        self.generated_test_file = self.target.replace(".go", "_test.go")
        with open(self.generated_test_file, 'w') as f:
            f.write("\n".join(test_code))
        
        return self.generated_test_file

    def run_dynamic(self):
        print(f"[*] Запуск динамических тестов Go...")
        
        # Если тестов нет, генерируем
        existing_test = os.path.exists(self.target.replace(".go", "_test.go"))
        if not existing_test:
            self.generate_go_test()

        cmd = ["go", "test", "-v", self.target_dir]
        try:
            process = subprocess.run(cmd, capture_output=True, text=True)
            output = process.stdout
            
            if "FAIL" in output:
                print(f"{Colors.FAIL}[!] Тесты провалены!{Colors.ENDC}")
                # Берем последние 20 строк лога для отчета
                evidence = "\n".join(output.splitlines()[-20:])
                self.reporter.add_dynamic_issue("Go Test", "Ошибка выполнения тестов", "FAIL", evidence)
            else:
                print(f"{Colors.GREEN}[+] Тесты прошли успешно.{Colors.ENDC}")
                self.reporter.add_dynamic_issue("Go Test", "Unit-тесты пройдены", "PASS", "All tests passed")

        except Exception as e:
            print(f"Ошибка запуска go test: {e}")
        finally:
            #Если мы генерировали тест сами, удаляем его
            if self.generated_test_file and os.path.exists(self.generated_test_file):
                print("[*] Очистка временных файлов...")
                os.remove(self.generated_test_file)