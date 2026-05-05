#!/usr/bin/env python3
import argparse
import os
import sys
from reportGenerator import ReportGenerator
from ethereumScan import EthereumScanner
from fabricScan import FabricScanner

# Описание профилей:
#   fast  — только SAST (Slither / Gosec + ChaincodeAnalyzer). Секунды. CI/CD.
#   deep  — SAST + быстрый DAST (Echidna 5k итераций / CCKit). Минуты. Pre-merge.
#   audit — SAST + полный DAST + символьное исполнение (Mythril / Fuzz). До часа. Перед релизом.

PROFILE_ETHEREUM = {
    "fast":  {"use_myth": False, "myth_timeout": 0,  "run_dynamic": False},
    "deep":  {"use_myth": True,  "myth_timeout": 30, "run_dynamic": True},
    "audit": {"use_myth": True,  "myth_timeout": 90, "run_dynamic": True},
}

def main():
    parser = argparse.ArgumentParser(
        description='SmartScan: Система комплексного анализа безопасности смарт-контрактов',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Профили анализа:
  fast   Только SAST (Slither/Gosec). Секунды. Подходит для CI на каждый коммит.
  deep   SAST + быстрый DAST (Echidna + Mythril 30с / CCKit). Минуты. Pre-merge проверка.
  audit  Полный анализ: SAST + Mythril 90с + Echidna + Fuzzing. Перед продакшн-деплоем.
        """
    )
    parser.add_argument('file', help='Путь к файлу смарт-контракта (.sol или .go)')
    parser.add_argument(
        '--profile', choices=['fast', 'deep', 'audit'], default='deep',
        help='Профиль анализа (default: deep)',
    )
    parser.add_argument('--html', action='store_true', help='Сгенерировать HTML отчет')

    args = parser.parse_args()

    target_file = os.path.abspath(args.file)
    if not os.path.exists(target_file):
        print(f"[-] Ошибка: Файл {target_file} не найден")
        sys.exit(1)

    reporter = ReportGenerator()

    print(f"=== SmartScan | Профиль: {args.profile.upper()} | Файл: {os.path.basename(target_file)} ===")

    if target_file.endswith(".sol"):
        reporter.set_meta("Ethereum", target_file)

        eth_cfg = PROFILE_ETHEREUM[args.profile]
        scanner = EthereumScanner(
            target_file, reporter,
            use_myth=eth_cfg["use_myth"],
            myth_timeout=eth_cfg["myth_timeout"],
        )
        scanner.run_static()

        if eth_cfg["run_dynamic"]:
            scanner.run_dynamic()

    elif target_file.endswith(".go"):
        reporter.set_meta("Hyperledger Fabric", target_file)
        scanner = FabricScanner(target_file, reporter)

        scanner.run_static()

        if args.profile == 'deep':
            scanner.run_dynamic(mode="cckit")
        elif args.profile == 'audit':
            scanner.run_dynamic(mode="cckit")
            scanner.run_dynamic(mode="fuzz")
        # fast: только статика

    else:
        print("[-] Формат файла не поддерживается (.sol или .go)")
        sys.exit(1)

    json_path = reporter.save_json()
    print(f"[+] Отчет сохранен: {json_path}")
    if args.html:
        html_path = reporter.save_html()
        print(f"[+] HTML отчет: {html_path}")

if __name__ == "__main__":
    main()