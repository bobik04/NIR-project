#!/usr/bin/env python3
import argparse
import os
import sys
from reportGenerator import ReportGenerator
from ethereumScan import EthereumScanner
from fabricScan import FabricScanner

def main():
    parser = argparse.ArgumentParser(description='SmartScan: Modular Security Analyzer')
    parser.add_argument('file', help='Путь к файлу смарт-контракта (.sol или .go)')
    parser.add_argument('--html', action='store_true', help='Сгенерировать HTML отчет (JSON генерируется автоматически)')
    
    parser.add_argument('--myth', action='store_true', help='Включить глубокий анализ Mythril (требуется время)')
    
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print("[-] Файл не найден")
        sys.exit(1)

    reporter = ReportGenerator()
    target_file = args.file

    print(f"=== SmartScan Started: {target_file} ===")

    if target_file.endswith(".sol"):
        reporter.set_meta("Ethereum", target_file)
        scanner = EthereumScanner(target_file, reporter, use_myth=args.myth)
        
        # Запуск этапов
        scanner.run_static()
        scanner.run_dynamic()

    elif target_file.endswith(".go"):
        reporter.set_meta("Hyperledger Fabric", target_file)
        scanner = FabricScanner(target_file, reporter)
        
        # Запуск этапов
        scanner.run_static()
        scanner.run_dynamic()

    else:
        print("[-] Неизвестный формат файла. Поддерживаются .sol и .go")
        sys.exit(1)

    # Генерация отчетов
    reporter.save_json()
    
    if args.html:
        reporter.save_html()

    print("=== Анализ завершен ===")

if __name__ == "__main__":
    main()