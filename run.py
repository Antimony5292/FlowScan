import os
import sys
import argparse

from src import ScannerEngine, ConsoleReporter, HtmlReportGenerator


if __name__ == "__main__":
    # 1. 定义参数解析器
    parser = argparse.ArgumentParser(
        description="A modular security scanner for AI workflows (n8n, Dify, etc.)"
    )
    
    # 2. 添加位置参数 'target' (必须提供)
    parser.add_argument(
        "target", 
        help="The path to the file or folder you want to scan."
    )
    parser.add_argument("-o", "--output", default='report.html', help="指定生成 HTML 报告的文件路径")
    
    # 3. 解析参数
    args = parser.parse_args()
    
    # 4. 检查路径是否存在 (在 Main 中做一次基础检查)
    if not os.path.exists(args.target):
        print(f"❌ Error: The path '{args.target}' does not exist.")
        sys.exit(1)

    # 5. 实例化并运行
    engine = ScannerEngine()
    

    found_issues = engine.scan_path(args.target)
    
    # 6. 输出结果
    ConsoleReporter.print_summary(found_issues, engine.stats)
    HtmlReportGenerator.generate(found_issues, engine.stats, args.target, args.output)