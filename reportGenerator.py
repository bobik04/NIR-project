import json
import os
from datetime import datetime

class ReportGenerator:
    def __init__(self):
        self.reports_dir = os.path.abspath("reports")
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
            
        self.data = {
            "timestamp": str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
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
        sev = severity.lower()
        if sev in self.data["summary"]:
            self.data["summary"][sev] += 1
        elif sev == "error" or sev == "high": # Маппинг для разных инструментов
            self.data["summary"]["high"] += 1

    def add_dynamic_issue(self, tool, description, status, evidence=""):
        self.data["dynamic_analysis"].append({
            "tool": tool,
            "description": description,
            "status": status,
            "evidence": evidence
        })

    def _get_report_path(self, ext):
        filename = os.path.basename(self.data["target_file"])
        # Убираем расширение исходного файла и добавляем метку времени для уникальности
        name = os.path.splitext(filename)[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return os.path.join(self.reports_dir, f"{name}_{timestamp}_report.{ext}")
    
    def save_json(self):
        path = self._get_report_path("json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=4, ensure_ascii=False)
        return path

    def save_html(self):
        path = self._get_report_path("html")
        
        # Цветовая схема для отчета
        html_content = f"""
        <html>
        <head>
            <meta charset="UTF-8">
            <title>SmartScan Report</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; max-width: 1000px; margin: 0 auto; padding: 20px; background-color: #f4f7f9; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
                .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }}
                .issue {{ border-left: 5px solid #ccc; padding: 10px 15px; margin: 10px 0; background: #fff; }}
                .high {{ border-left-color: #e74c3c; }}
                .medium {{ border-left-color: #f39c12; }}
                .low {{ border-left-color: #3498db; }}
                .pass {{ color: #27ae60; font-weight: bold; }}
                .fail {{ color: #c0392b; font-weight: bold; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }}
                pre {{ background: #272822; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Отчет анализа безопасности</h1>
                <p>Файл: <b>{self.data['target_file']}</b> | Платформа: {self.data['platform']}</p>
                <p>Дата сканирования: {self.data['timestamp']}</p>
            </div>

            <div class="card">
                <h2>Сводка уязвимостей</h2>
                <table>
                    <tr>
                        <th>Высокий риск</th><th>Средний риск</th><th>Низкий риск</th>
                    </tr>
                    <tr>
                        <td style="color:#e74c3c; font-size: 24px; font-weight: bold;">{self.data['summary']['high'] + self.data['summary']['critical']}</td>
                        <td style="color:#f39c12; font-size: 24px; font-weight: bold;">{self.data['summary']['medium']}</td>
                        <td style="color:#3498db; font-size: 24px; font-weight: bold;">{self.data['summary']['low']}</td>
                    </tr>
                </table>
            </div>

            <div class="card">
                <h2>Результаты статического анализа (SAST)</h2>
                {"<p>Уязвимостей не найдено.</p>" if not self.data['static_analysis'] else ""}
                {"".join([f'''
                <div class="issue {item['severity'].lower()}">
                    <b>{item['type']}</b> ({item['tool']})<br>
                    <small>{item['location']}</small><br>
                    {item['description']}
                </div>
                ''' for item in self.data['static_analysis']])}
            </div>

            <div class="card">
                <h2>Результаты динамического анализа (DAST)</h2>
                {"".join([f'''
                <div class="issue">
                    <b>{item['tool']}</b>: <span class="{item['status'].lower()}">{item['status']}</span><br>
                    <i>{item['description']}</i>
                    <pre>{item['evidence']}</pre>
                </div>
                ''' for item in self.data['dynamic_analysis']])}
            </div>
        </body>
        </html>
        """
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return path