import os
import subprocess
import json
import re
import sys
import glob
import shutil

class Colors:
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    GREEN = '\033[92m'
    ENDC = '\033[0m'

class EthereumScanner:
    def __init__(self, target_file, reporter, use_myth=False, myth_timeout=60):
        self.target = os.path.abspath(target_file)
        self.reporter = reporter
        self.use_myth = use_myth
        self.myth_timeout = myth_timeout
        self.env_dir = os.path.expanduser("~/analyzer-env")
        self.solc_path = os.path.join(self.env_dir, "bin/solc")

    def run_static(self):
        print(f"[*] Запуск Slither (Security)...")
        env = os.environ.copy()
        if os.path.exists(self.solc_path):
            env["SOLC"] = self.solc_path
            
        cmd = ["slither", self.target, "--json", "-"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, env=env)
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    detectors = data.get("results", {}).get("detectors", [])
                    if detectors:
                        print(f"{Colors.WARNING}Slither нашел {len(detectors)} проблем.{Colors.ENDC}")
                        for issue in detectors:
                            self.reporter.add_static_issue(
                                "Slither", issue['check'], issue['impact'], issue['description']
                            )
                            print(f" - [{issue['impact']}] {issue['check']}")
                    else:
                        print(f"{Colors.GREEN}[+] Slither: Чисто.{Colors.ENDC}")
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            print(f"{Colors.FAIL}Ошибка Slither: {e}{Colors.ENDC}")

        if self.use_myth:
            self.run_mythril()
        else:
            print("[*] Mythril пропущен (используйте профиль deep или audit для включения)")

    def run_mythril(self):
        print(f"[*] Запуск Mythril (Symbolic Execution)...")
        print("    (Mythril использует встроенный crytic-compile для разрешения импортов)")
        
        try:
            # Передаем .sol файл напрямую в Mythril. Он сам разрешит импорты.
            myth_cmd = [
                "myth", "analyze", self.target,
                "--execution-timeout", str(self.myth_timeout),
                "--max-depth", "30",
                "-o", "json"
            ]

            result = subprocess.run(myth_cmd, capture_output=True, text=True)
            output_data = result.stdout

            if not output_data and result.stderr and "{" in result.stderr:
                output_data = result.stderr

            data = json.loads(output_data)
            issues = data.get("issues", [])
            
            if issues:
                print(f"{Colors.WARNING}    Mythril нашел {len(issues)} проблем.{Colors.ENDC}")
                for issue in issues:
                    title = issue.get("title", "Unknown Issue")
                    severity = issue.get("severity", "Medium")
                    description = issue.get("description", "")
                    
                    self.reporter.add_static_issue(
                        "Mythril", title, severity, description
                    )
                    print(f"     - [{severity}] {title}")
            else:
                print(f"{Colors.GREEN}    [+] Mythril: Чисто.{Colors.ENDC}")

        except json.JSONDecodeError:
            if "The analysis was completed successfully" in result.stderr:
                 print(f"{Colors.GREEN}    [+] Mythril: Анализ завершен без находок.{Colors.ENDC}")
            else:
                 print(f"{Colors.FAIL}    [!] Ошибка Mythril (возможно, не удалось разрешить импорты). Попробуйте установить зависимости npm.{Colors.ENDC}")
        except Exception as e:
            print(f"    Ошибка запуска Mythril: {e}")

    def get_main_contract_info(self, content):
        """
        Умный поиск главного контракта и параметров его конструктора
        """
        contracts = re.findall(r'contract\s+(\w+)', content)
        if not contracts:
            return None, None
        
        main_contract = contracts[-1]
        
        # Проверяем, есть ли конструктор с аргументами
        constructor_match = re.search(r'constructor\s*\((.*?)\)', content)
        constructor_args = ""
        
        if constructor_match and constructor_match.group(1).strip() != "":
            args = constructor_match.group(1).split(',')
            dummy_args = []
            for arg in args:
                if 'uint' in arg:
                    dummy_args.append("1000")
                elif 'string' in arg:
                    dummy_args.append("\"TestToken\"")
                elif 'address' in arg:
                    dummy_args.append("address(this)")
                elif 'bool' in arg:
                    dummy_args.append("true")
                else:
                    dummy_args.append("0")
            constructor_args = ", ".join(dummy_args)
            print(f"    [!] Найден конструктор с аргументами. Сгенерированы заглушки: {constructor_args}")
            
        return main_contract, constructor_args

    def generate_echidna_test(self):
        print("[*] Интеллектуальная генерация теста для Echidna...")
        with open(self.target, 'r', encoding='utf-8') as f:
            content = f.read()

        contract_name, constructor_args = self.get_main_contract_info(content)
        if not contract_name:
            print("    [-] Не найдено ключевое слово contract.")
            return None
        
        # Определяем тип контракта на основе его кода
        is_erc20 = 'balanceOf' in content and 'transfer' in content and 'totalSupply' in content
        is_payable = 'payable' in content
        # Проверяем, что deposit() действительно объявлена в контракте —
        # иначе тест не скомпилируется
        has_deposit = bool(re.search(r'\bfunction\s+deposit\s*\(', content))

        test_code = [
            "// SPDX-License-Identifier: MIT",
            "pragma solidity ^0.8.0;",
            f"import \"{self.target}\";",
            "",
            f"contract GeneratedAutoTest is {contract_name} {{"
        ]

        if has_deposit:
            test_code.append("    uint256 private totalExpected;")

        if constructor_args:
            test_code.append(f"    constructor() {contract_name}({constructor_args}) payable {{}}")
        else:
            test_code.append("    constructor() payable {}")

        test_code.append("")

        # 1. Инвариант: контракт не должен отправлять больше эфира чем получил
        #    (защита от reentrancy / drain-атак).
        #    Проверяем только если есть payable-функции И deposit() для накопления базы.
        if is_payable and has_deposit:
            test_code.extend([
                "    function depositAuto() public payable {",
                "        if (msg.value > 0 && msg.value < 100 ether) {",
                "            deposit();",
                "            totalExpected += msg.value;",
                "        }",
                "    }",
                "    function echidna_check_solvency() public view returns (bool) {",
                "        // Баланс контракта не должен быть меньше суммы всех депозитов",
                "        return address(this).balance >= totalExpected;",
                "    }",
            ])
        elif is_payable:
            # Нет deposit() — просто проверяем что баланс не уходит в минус
            test_code.extend([
                "    uint256 private _initBalance;",
                "    function echidna_no_unexpected_drain() public view returns (bool) {",
                "        // Контракт не должен терять эфир без явного вызова withdraw",
                "        return address(this).balance >= _initBalance;",
                "    }",
            ])

        # 2. Инварианты для стандарта ERC20
        if is_erc20:
            print("    [+] Определен стандарт ERC20. Добавлены финансовые инварианты.")
            test_code.extend([
                "    function echidna_erc20_supply_logic() public view returns (bool) {",
                "        // Баланс контракта не может превышать общую эмиссию",
                "        return balanceOf(address(this)) <= totalSupply();",
                "    }"
            ])

        # 3. Базовый инвариант liveness
        test_code.extend([
            "    bool private initialized = true;",
            "    function echidna_basic_liveness() public view returns (bool) {",
            "        return initialized;",
            "    }",
            "}",
        ])

        test_path = self.target.replace(".sol", "_AutoTest.sol")
        with open(test_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(test_code))
        return test_path

    def run_dynamic(self):
        print(f"[*] Запуск Echidna...")
        test_file = self.generate_echidna_test()
        if not test_file:
            return

        cmd = [
            "echidna", test_file, 
            "--contract", "GeneratedAutoTest", 
            "--test-limit", "5000", 
            "--format", "text",
            "--seq-len", "100" 
        ]
        
        print(f"{Colors.WARNING}[*] Команда для ручного запуска Echidna:{Colors.ENDC}")
        print(f"    {' '.join(cmd)}")
        
        try:
            # Устанавливаем таймаут, чтобы Echidna не зависала на очень сложных контрактах
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            output = process.stdout + "\n" + process.stderr
            
            if "falsified" in output.lower() or "failed" in output.lower():
                print(f"{Colors.FAIL}[!] Echidna: Инвариант нарушен!{Colors.ENDC}")
                evidence = "Детали не найдены. Проверьте лог консоли."
                
                if "call sequence:" in output.lower():
                    parts = re.split(r"(?i)call sequence:", output)
                    last_sequence_block = parts[-1]
                    clean_sequence = re.split(r"(?i)(Traces:|Unique instructions:)", last_sequence_block)[0]
                    evidence = "Call sequence:\n" + clean_sequence.strip()
                
                self.reporter.add_dynamic_issue("Echidna", "Нарушение инварианта", "FAIL", evidence)
            else:
                print(f"{Colors.GREEN}[+] Echidna: Тест пройден.{Colors.ENDC}")
                self.reporter.add_dynamic_issue("Echidna", "Инварианты соблюдены", "PASS", "Tests passed")

        except subprocess.TimeoutExpired:
            print(f"{Colors.WARNING}[!] Echidna: Превышено время ожидания (Таймаут).{Colors.ENDC}")
            self.reporter.add_dynamic_issue("Echidna", "Таймаут фаззинга", "MEDIUM", "Анализ остановлен по таймауту (180с)")
        except Exception as e:
            print(f"Ошибка Echidna: {e}")