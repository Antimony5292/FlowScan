import os
from typing import List, Dict, Any, Type
from src.utils import Issue, ScanStats
# ==========================================
# 5. 展示层 (Visualization)
# ==========================================

class HtmlReportGenerator:
    """生成漂亮的 HTML 报告"""
    
    TEMPLATE = """
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AI Workflow 安全扫描报告</title>
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
                    <h1>🛡️ AI Workflow 安全扫描报告</h1>
                    <div style="text-align: right; font-size: 14px; color: #666;">
                        扫描时间: {scan_time}<br>
                        扫描对象: {target_path}
                    </div>
                </div>

                <div class="stats-grid">
                    <div class="card"><h3>{scanned_count}</h3><p>已扫描文件</p></div>
                    <div class="card"><h3 style="color: {issue_color}">{issue_count}</h3><p>发现问题</p></div>
                    <div class="card"><h3 style="color: var(--red)">{files_with_issues}</h3><p>风险文件</p></div>
                    <div class="card"><h3>{high_severity}</h3><p>高危漏洞</p></div>
                </div>

                <h2>详细问题列表</h2>
                {table_content}
                
            </div>
        </body>
        </html>
    """

    @staticmethod
    def generate(issues: List[Issue], stats: ScanStats, target_path: str, output_file: str):
        # 准备数据
        high_severity = stats.severity_counts.get("High", 0)
        issue_color = "#dc3545" if stats.issue_count > 0 else "#198754"
        
        # 构建表格内容
        if not issues:
            table_content = "<div class='empty-state'><h2>🎉 太棒了！</h2><p>未发现任何已知的安全风险。</p></div>"
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
                        <th width="80">等级</th>
                        <th width="150">类型</th>
                        <th width="300">文件</th>
                        <th>详细信息</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
            """

        # 填充模板
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
            print(f"\n✅ HTML 报告已生成: {os.path.abspath(output_file)}")
        except Exception as e:
            print(f"❌ 生成报告失败: {e}")

class ConsoleReporter:
    """传统的控制台输出"""
    @staticmethod
    def print_summary(issues: List[Issue], stats: ScanStats):
        print("\n" + "="*60)
        print(f"🛡️  扫描完成")
        print(f"扫描文件: {stats.scanned_count} | 发现问题: {stats.issue_count} | 错误: {stats.error_count}")
        print("="*60)
        
        if issues:
            print(f"| {'等级':<8} | {'文件名':<30} | {'详情'}")
            print(f"| {'-'*8} | {'-'*30} | {'-'*20}")
            for issue in issues:
                fname = os.path.basename(issue.file_path)
                if len(fname) > 28: fname = fname[:25] + "..."
                print(f"| {issue.severity:<8} | {fname:<30} | {issue.detail}")
        else:
            print("✅ 未发现安全问题。")
        print("\n")
