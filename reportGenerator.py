import json
import os
from datetime import datetime

class ReportGenerator:
    def __init__(self):
        # Автоматическое создание папки reports
        self.reports_dir = os.path.abspath("reports")
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
            
        self.data = {
            "timestamp": str(datetime.now()),
            "platform": "unknown",
            "target_file": "",
            "static_analysis": [],
            "dynamic_analysis": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0}
        }

    def set_meta(self, platform, target):
        self.data["platform"] = platform
        self.data["target_file"] = target

    def add_static_issue(self, tool, issue_type, severity, description, location=""):
        self.data["static_analysis"].append({
            "tool": tool,
            "type": issue_type,
            "severity": severity,
            "description": description,
            "location": location
        })
        sev_key = severity.lower()
        if sev_key in self.data["summary"]:
            self.data["summary"][sev_key] += 1

    def add_dynamic_issue(self, tool, description, status, evidence=""):
        self.data["dynamic_analysis"].append({
            "tool": tool,
            "description": description,
            "status": status,
            "evidence": evidence
        })
        if status == "FAIL":
            self.data["summary"]["critical"] += 1

    def _get_report_path(self, ext):
        filename = os.path.basename(self.data["target_file"])
        # Убираем расширение исходного файла и добавляем метку времени для уникальности
        name = os.path.splitext(filename)[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return os.path.join(self.reports_dir, f"{name}_{timestamp}_report.{ext}")

    def save_json(self):
        output_path = self._get_report_path("json")
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=4, ensure_ascii=False)
        print(f"[+] Отчет сохранен автоматически: {output_path}")

    def save_html(self):
        output_path = self._get_report_path("html")
        html = f"""
        <html>
        <head>
            <title>SmartScan Report - {self.data['target_file']}</title>
            <style>
                body {{ font-family: sans-serif; padding: 20px; background: #f0f2f5; }}
                .container {{ background: white; padding: 30px; border-radius: 8px; max-width: 900px; margin: auto; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                h1 {{ color: #333; border-bottom: 2px solid #eee; padding-bottom: 10px; }}
                .summary {{ display: flex; gap: 20px; margin-bottom: 30px; }}
                .card {{ padding: 15px; background: #fafafa; border: 1px solid #eee; border-radius: 5px; flex: 1; text-align: center; }}
                .high {{ color: #d9534f; font-weight: bold; }}
                .medium {{ color: #f0ad4e; font-weight: bold; }}
                .issue {{ border-left: 4px solid #ddd; padding: 10px 15px; margin-bottom: 10px; background: #fff; border: 1px solid #eee; }}
                .issue.High {{ border-left-color: #d9534f; }}
                .issue.Medium {{ border-left-color: #f0ad4e; }}
                .fail {{ background-color: #fff5f5; border-left: 4px solid #d9534f; }}
                pre {{ background: #f8f9fa; padding: 10px; overflow-x: auto; font-size: 0.9em; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Отчет безопасности: {os.path.basename(self.data['target_file'])}</h1>
                <p>Платформа: <b>{self.data['platform']}</b> | Дата: {self.data['timestamp']}</p>
                
                <div class="summary">
                    <div class="card">Critical: <span class="high">{self.data['summary']['critical']}</span></div>
                    <div class="card">High: <span class="high">{self.data['summary']['high']}</span></div>
                    <div class="card">Medium: <span class="medium">{self.data['summary']['medium']}</span></div>
                </div>

                <h2>Статический анализ</h2>
                {''.join([f'<div class="issue {i["severity"]}"><b>[{i["severity"]}] {i["type"]}</b><br>{i["description"]}</div>' for i in self.data['static_analysis']])}
                
                <h2>Динамический анализ</h2>
                {''.join([f'<div class="issue { "fail" if i["status"] == "FAIL" else "" }"><b>{i["tool"]}</b>: {i["status"]}<br>{i["description"]}<br><pre>{i["evidence"]}</pre></div>' for i in self.data['dynamic_analysis']])}
            </div>
        </body>
        </html>
        """
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[+] HTML отчет сохранен: {output_path}")