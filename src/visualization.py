import os
from typing import List, Dict, Any, Type
from src.utils import Issue, ScanStats
# ==========================================
# 5. Report Generators (HTML & CLI)
# ==========================================

class HtmlReportGenerator:
    
    TEMPLATE = """
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AI Workflow Security Report</title>
            <style>
                :root {{ --bg-color: #f8f9fa; --card-bg: #ffffff; --text-color: #333; --border-color: #e9ecef; --red: #dc3545; --orange: #fd7e14; --blue: #0d6efd; }}
                body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background-color: var(--bg-color); color: var(--text-color); margin: 0; padding: 20px; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; border-bottom: 2px solid var(--border-color); padding-bottom: 20px; }}
                .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
                .card {{ background: var(--card-bg); padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); text-align: center; }}
                .card h3 {{ margin: 0; font-size: 36px; color: var(--blue); }}
                .card p {{ margin: 5px 0 0; color: #666; font-size: 14px; }}
                .issue-table {{ width: 100%; border-collapse: collapse; background: var(--card-bg); border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }}
                .issue-table th, .issue-table td {{ padding: 15px; text-align: left; border-bottom: 1px solid var(--border-color); }}
                .issue-table th {{ background-color: #f1f3f5; font-weight: 600; }}
                .badge {{ padding: 5px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; color: white; display: inline-block; }}
                .badge-High {{ background-color: var(--red); }}
                .badge-Medium {{ background-color: var(--orange); }}
                .badge-Low {{ background-color: #6c757d; }}
                .file-path {{ font-family: monospace; color: #555; }}
                .empty-state {{ text-align: center; padding: 50px; color: #adb5bd; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ AI Workflow Security Report</h1>
                    <div style="text-align: right; font-size: 14px; color: #666;">
                        Scan Time: {scan_time}<br>
                        Target: {target_path}
                    </div>
                </div>

                <div class="stats-grid">
                    <div class="card"><h3>{scanned_count}</h3><p>Files Scanned</p></div>
                    <div class="card"><h3 style="color: {issue_color}">{issue_count}</h3><p>Issues Found</p></div>
                    <div class="card"><h3 style="color: var(--red)">{files_with_issues}</h3><p>Risky Files</p></div>
                    <div class="card"><h3>{high_severity}</h3><p>Critical Issues</p></div>
                </div>

                <h2>Detailed Findings</h2>
                {table_content}
                
            </div>
        </body>
        </html>
    """

    @staticmethod
    def generate(issues: List[Issue], stats: ScanStats, target_path: str, output_file: str):
        # Prepare data
        high_severity = stats.issue_distribution.get("High", 0)
        issue_color = "#dc3545" if stats.issue_count > 0 else "#198754"
        
        # Build table content
        if not issues:
            table_content = "<div class='empty-state'><h2>🎉 Awesome!</h2><p>No security issues detected.</p></div>"
        else:
            rows = ""
            for issue in issues:
                rows += f"""
                <tr>
                    <td><span class="badge badge-{issue.severity}">{issue.severity}</span></td>
                    <td>{issue.issue_type}</td>
                    <td class="file-path">{os.path.basename(issue.file_path)}<br><span style="font-size:12px;color:#999">{issue.file_path}</span></td>
                    <td>{issue.detail}</td>
                </tr>
                """
            table_content = f"""
            <table class="issue-table">
                <thead>
                    <tr>
                        <th width="80">Severity</th>
                        <th width="150">Type</th>
                        <th width="300">File</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
            """

        # Fill template
        html_content = HtmlReportGenerator.TEMPLATE.format(
            scan_time=stats.start_time,
            target_path=target_path,
            scanned_count=stats.scanned_count,
            issue_count=stats.issue_count,
            files_with_issues=stats.files_with_issues,
            high_severity=high_severity,
            issue_color=issue_color,
            table_content=table_content
        )

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"\n✅ HTML report generated: {os.path.abspath(output_file)}")
        except Exception as e:
            print(f"❌ Failed to generate report: {e}")

class ConsoleReporter:
    """Traditional console output"""
    @staticmethod
    def print_summary(issues: List[Issue], stats: ScanStats):
        print("\n" + "="*60)
        print(f"🛡️  Scan Complete")
        print(f"Scanned: {stats.scanned_count} | Issues: {stats.issue_count} | Errors: {stats.error_count}")
        print("="*60)
        
        if issues:
            print(f"| {'Severity':<8} | {'Filename':<30} | {'Details'}")
            print(f"| {'-'*8} | {'-'*30} | {'-'*20}")
            for issue in issues:
                fname = os.path.basename(issue.file_path)
                if len(fname) > 28: fname = fname[:25] + "..."
                print(f"| {issue.severity:<8} | {fname:<30} | {issue.detail}")
        else:
            print("✅ No security issues found.")
        print("\n")
