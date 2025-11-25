import os
from abc import ABC, abstractmethod
import yaml
import json
from typing import List, Dict, Any, Type

from src.utils import Issue, ScanStats
from src.rules import SecurityRules

# ==========================================
# 3. 扫描器基类与实现 (Scanner Modules)
# ==========================================

class BaseScanner(ABC):
    """Workflow Scanner Base"""
    
    @abstractmethod
    def identify(self, file_path: str) -> bool:
        """判断该文件是否属于当前扫描器负责的类型"""
        pass

    @abstractmethod
    def scan(self, file_path: str) -> List[Issue]:
        pass

class N8nScanner(BaseScanner):
    
    def identify(self, file_path: str) -> bool:
        # n8n usually .json
        return file_path.endswith('.json')

    def scan(self, file_path: str) -> List[Issue]:
        issues = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # 1. Check Meta Data
            wf_name = data.get('name', 'Untitled')
            secret_hits = SecurityRules.check_hardcoded_secrets(wf_name, "Workflow Name")
            for hit in secret_hits:
                issues.append(Issue(file_path, "Hardcoded Secret", hit, "High"))

            # 2. Check Nodes
            for node in data.get('nodes', []):
                node_name = node.get('name', 'Unknown')
                node_type = node.get('type', '')
                params = str(node.get('parameters', {}))
                
                # Rule A: Secrets / Credentials
                param_hits = SecurityRules.check_hardcoded_secrets(params, f"Node: {node_name}")
                for hit in param_hits:
                    issues.append(Issue(file_path, "Hardcoded Secret", hit, "High"))
                
                # Rule B: Injection
                injection_hits = SecurityRules.check_prompt_injection(node_type, params)
                for hit in injection_hits:
                    issues.append(Issue(file_path, "Prompt Injection Risk", f"Node '{node_name}': {hit}", "Medium"))

        except Exception as e:
            print(f"DEBUG: Error parsing n8n file {file_path}: {e}")
        
        return issues


class DifyScanner(BaseScanner):
    """
    (扩展示例) Dify 专用扫描器
    Dify 导出通常是 YAML (DSL)
    """
    
    def identify(self, file_path: str) -> bool:
        return file_path.endswith('.yml') or file_path.endswith('.yaml')

    def scan(self, file_path: str) -> List[Issue]:
        issues = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # 假设使用了 pyyaml
                data = yaml.safe_load(f)
            
            # Dify 的结构不同，通常有 'app' 和 'workflow' 键
            if not data: return []
            
            app_name = data.get('app', {}).get('name', '')
            if "test_key" in app_name:
                issues.append(Issue(file_path, "Hardcoded Secret", "App name contains 'test_key'", "High"))
                
            # 这里可以添加针对 Dify Block 的遍历逻辑...
            
        except Exception:
            pass # 暂时忽略 Dify 错误
            
        return issues

# ==========================================
# 4. 核心引擎 (Core Engine)
# ==========================================

class ScannerEngine:
    def __init__(self):
        # 注册所有可用的扫描器
        self.scanners: List[BaseScanner] = [
            N8nScanner(),
            # DifyScanner() 
            # 未来可以在这里添加 LangChainScanner()
        ]
        self.stats = ScanStats()

    def _get_scanner_for_file(self, file_path: str) -> BaseScanner:
        """根据文件特征自动选择合适的扫描器"""
        for scanner in self.scanners:
            if scanner.identify(file_path):
                return scanner
        return None

    def scan_path(self, path: str) -> List[Issue]:
        """主入口：支持文件或文件夹"""
        all_issues = []
        
        # 1. 确定文件列表
        files_to_scan = []
        if os.path.isfile(path):
            files_to_scan.append(path)
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    files_to_scan.append(os.path.join(root, file))
        else:
            print(f"❌ Path not found: {path}")
            return []

        print(f"🚀 Starting scan on: {path} (Files found: {len(files_to_scan)})")

        # 2. 执行扫描
        for file_path in files_to_scan:
            scanner = self._get_scanner_for_file(file_path)
            
            if scanner:
                self.stats.scanned_count += 1
                try:
                    file_issues = scanner.scan(file_path)
                    if file_issues:
                        all_issues.extend(file_issues)
                        self.stats.issue_count += len(file_issues)
                        for i in file_issues:
                            self.stats.issue_distribution[i.issue_type] += 1
                except Exception as e:
                    self.stats.error_count += 1
                    print(f"Error scanning {file_path}: {e}")
            else:
                # print(f"Skipping unsupported file: {file_path}")
                pass

        return all_issues