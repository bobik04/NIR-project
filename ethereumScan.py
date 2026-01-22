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
    def __init__(self, target_file, reporter, use_myth=False):
        self.target = os.path.abspath(target_file)
        self.reporter = reporter
        self.use_myth = use_myth # Флаг использования Mythril
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

        # Mythril запускается только если передан флаг --myth
        if self.use_myth:
            self.run_mythril()
        else:
            print("[*] Mythril пропущен (используйте флаг --myth для включения)")

    def run_mythril(self):
        print(f"[*] Запуск Mythril (Symbolic Execution) через байт-код...")
        print("    (Компиляция и анализ могут занять время...)")
        
        build_dir = "build"
        
        #Компиляция в байт-код
        try:
            if os.path.exists(build_dir):
                shutil.rmtree(build_dir)
            os.makedirs(build_dir)

            # Формируем команду solc: solc --bin <file> -o build/ --overwrite
            solc_cmd = [self.solc_path if os.path.exists(self.solc_path) else "solc", 
                        "--bin", self.target, 
                        "-o", build_dir, 
                        "--overwrite"]
            
            subprocess.run(solc_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            
            # Ищем сгенерированные .bin файлы
            bin_files = glob.glob(os.path.join(build_dir, "*.bin"))
            if not bin_files:
                print(f"{Colors.FAIL}[!] Не удалось скомпилировать байт-код.{Colors.ENDC}")
                return

        except subprocess.CalledProcessError as e:
            print(f"{Colors.FAIL}[!] Ошибка компиляции Solc: {e.stderr.decode()}{Colors.ENDC}")
            return
        except Exception as e:
            print(f"{Colors.FAIL}[!] Ошибка подготовки Mythril: {e}{Colors.ENDC}")
            return

        # 2. Анализ каждого скомпилированного контракта
        for bin_file in bin_files:
            contract_name = os.path.basename(bin_file).replace(".bin", "")
            print(f"    -> Анализ контракта: {contract_name}")
            
            try:
                with open(bin_file, 'r') as f:
                    bytecode = f.read().strip()
                
                if not bytecode:
                    continue

                myth_cmd = [
                    "myth", "analyze",
                    "-c", bytecode,
                    "--execution-timeout", "60",
                    "--max-depth", "50",
                    "--solver-timeout", "60000",
                    "-o", "json"
                ]

                result = subprocess.run(myth_cmd, capture_output=True, text=True)
                
                # Парсинг результатов
                output_data = result.stdout
                # Fallback если JSON в stderr
                if not output_data and result.stderr and "{" in result.stderr:
                    output_data = result.stderr

                data = json.loads(output_data)
                issues = data.get("issues", [])
                
                if issues:
                    print(f"{Colors.WARNING}    Mythril нашел {len(issues)} проблем в {contract_name}.{Colors.ENDC}")
                    for issue in issues:
                        title = issue.get("title", "Unknown Issue")
                        severity = issue.get("severity", "Medium")
                        description = issue.get("description", "")
                        
                        self.reporter.add_static_issue(
                            f"Mythril ({contract_name})", title, severity, description
                        )
                        print(f"     - [{severity}] {title}")
                else:
                    print(f"{Colors.GREEN}    [+] Mythril: Чисто.{Colors.ENDC}")

            except json.JSONDecodeError:
                if "The analysis was completed successfully" in result.stderr:
                     print(f"{Colors.GREEN}    [+] Mythril: Анализ завершен без находок.{Colors.ENDC}")
                else:
                     pass
            except Exception as e:
                print(f"    Ошибка анализа {contract_name}: {e}")

        # Очистка
        if os.path.exists(build_dir):
            shutil.rmtree(build_dir)

    def generate_echidna_test(self):
        print("[*] Генерация теста для Echidna...")
        with open(self.target, 'r') as f:
            content = f.read()

        match = re.search(r'contract\s+(\w+)', content)
        if not match:
            return None
        contract_name = match.group(1)
        
        has_balances = 'mapping(address => uint256)' in content and 'balances' in content

        test_code = [
            "// SPDX-License-Identifier: MIT",
            f"pragma solidity ^0.8.28;",
            f"import \"{self.target}\";",
            "",
            f"contract GeneratedAutoTest is {contract_name} {{",
            "    uint256 private totalExpected;",
            "    constructor() payable {}",
            ""
        ]

        if has_balances:
            test_code.extend([
                "    function depositAuto() public payable {",
                "        if (msg.value > 0 && msg.value < 100 ether) {",
                "            deposit();",
                "            totalExpected += msg.value;",
                "        }",
                "    }",
                "    function echidna_check_solvency() public view returns (bool) {",
                "        return address(this).balance >= totalExpected;",
                "    }"
            ])
        else:
            test_code.extend([
                "    function echidna_not_empty() public view returns (bool) { return true; }"
            ])

        test_code.append("}")
        test_path = self.target.replace(".sol", "_AutoTest.sol")
        with open(test_path, 'w') as f:
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
        
        try:
            process = subprocess.run(cmd, capture_output=True, text=True)
            output = process.stdout + "\n" + process.stderr
            
            if "falsified" in output.lower() or "failed" in output.lower():
                print(f"{Colors.FAIL}[!] Echidna: Инвариант нарушен!{Colors.ENDC}")
                
                evidence = "Детали не найдены."
                if "Call Sequence" in output:
                    parts = re.split(r"Call Sequence", output, flags=re.IGNORECASE)
                    evidence = "Call Sequence" + parts[-1].split("---")[0].strip()
                elif "Shrinking" in output:
                    evidence = output.split("Shrinking")[-1].strip()
                
                self.reporter.add_dynamic_issue("Echidna", "Нарушение инварианта", "FAIL", evidence)
            else:
                print(f"{Colors.GREEN}[+] Echidna: Тест пройден.{Colors.ENDC}")
                self.reporter.add_dynamic_issue("Echidna", "Инварианты соблюдены", "PASS", "Tests passed")

        except Exception as e:
            print(f"Ошибка Echidna: {e}")
        finally:
            if os.path.exists(test_file):
                os.remove(test_file)