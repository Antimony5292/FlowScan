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
        # n8n workflows usually end with .json and contain a 'nodes' key
        if not file_path.endswith('.json'):
            return False
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return isinstance(data, dict) and 'nodes' in data
        except:
            return False

    def scan(self, file_path: str) -> List[Issue]:
        issues = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            wf_name = data.get('name', 'Untitled')
            
            # 1. Check Nodes
            for node in data.get('nodes', []):
                node_name = node.get('name', 'Unknown')
                node_type = node.get('type', '')
                params = node.get('parameters', {})
                param_str = json.dumps(params)
                
                context = f"Node '{node_name}' ({node_type})"

                # Rule: Hardcoded Secrets
                secret_hits = SecurityRules.check_hardcoded_secrets(param_str, context)
                for hit in secret_hits:
                    issues.append(Issue(file_path, "Hardcoded Secret", hit, "High"))
                
                # Rule: PII Disclosure
                pii_hits = SecurityRules.check_pii_disclosure(param_str, context)
                for hit in pii_hits:
                    issues.append(Issue(file_path, "PII Leakage", hit, "Medium"))

                # Rule: Insecure HTTP
                url = params.get('url', '')
                if url:
                    http_hits = SecurityRules.check_insecure_http(url, context)
                    for hit in http_hits:
                        issues.append(Issue(file_path, "Insecure Transport", hit, "Medium"))

                # Rule: Dangerous Code (n8n.code)
                if "n8n-nodes-base.code" in node_type:
                    js_code = params.get('jsCode', '')
                    code_hits = SecurityRules.check_dangerous_code(js_code, "javascript", context)
                    for hit in code_hits:
                        issues.append(Issue(file_path, "Dangerous Code", hit, "High"))

                # Rule: Prompt Injection & Leaking (AI nodes)
                prompt = params.get('prompt', '') or params.get('text', '') or params.get('systemPrompt', '')
                if prompt:
                    prompt_hits = SecurityRules.check_prompt_risks(str(prompt), context)
                    for hit in prompt_hits:
                        issues.append(Issue(file_path, "Prompt Security Risk", hit, "Medium"))

            # 2. Excessive Agency (Graph Analysis)
            issues.extend(self._check_excessive_agency(data, file_path))

        except Exception as e:
            print(f"DEBUG: Error parsing n8n file {file_path}: {e}")
        
        return issues

    def _check_excessive_agency(self, data: Dict[str, Any], file_path: str) -> List[Issue]:
        """n8n 拓扑审计：寻找 AI -> Destructive 且无 Approval 的路径"""
        issues = []
        nodes = {n['name']: n for n in data.get('nodes', [])}
        connections = data.get('connections', {})

        # 1. 识别触发源（如 AI 节点或 Webhook）
        trigger_nodes = []
        for name, node in nodes.items():
            ntype = node.get('type', '').lower()
            if any(t in ntype for t in ["llm", "chat", "webhook", "ai"]):
                trigger_nodes.append(name)

        # 2. 深度优先搜索 (DFS) 查找危险路径
        for start_node in trigger_nodes:
            visited = set()
            stack = [(start_node, False)] # (node_name, seen_approval)
            
            while stack:
                curr_name, seen_approval = stack.pop()
                if curr_name in visited: continue
                visited.add(curr_name)

                curr_node = nodes.get(curr_name)
                if not curr_node: continue

                # 更新审批状态
                if SecurityRules.is_approval_node(curr_node.get('type', '')):
                    seen_approval = True

                # 检查是否为破坏性节点且未经过审批
                if not seen_approval and SecurityRules.is_destructive_node(curr_node.get('type', ''), curr_node.get('parameters', {})):
                    issues.append(Issue(
                        file_path, 
                        "Excessive Agency", 
                        f"Potentially destructive node '{curr_name}' is triggered by '{start_node}' without manual approval.", 
                        "High"
                    ))

                # 获取下游节点
                node_conns = connections.get(curr_name, {}).get('main', [])
                for conn_group in node_conns:
                    for target in conn_group:
                        stack.append((target.get('node'), seen_approval))

        return issues


class DifyScanner(BaseScanner):
    
    def identify(self, file_path: str) -> bool:
        # Dify DSL usually .yml or .yaml and contains 'workflow' or 'app'
        if not (file_path.endswith('.yml') or file_path.endswith('.yaml')):
            return False
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                return isinstance(data, dict) and ('workflow' in data or 'app' in data)
        except:
            return False

    def scan(self, file_path: str) -> List[Issue]:
        issues = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            if not data: return []
            
            # Dify workflow nodes are typically in data['workflow']['nodes']
            nodes = data.get('workflow', {}).get('nodes', [])
            for node in nodes:
                node_name = node.get('data', {}).get('title', 'Unknown')
                node_type = node.get('data', {}).get('type', '')
                node_data = node.get('data', {})
                node_str = json.dumps(node_data)
                
                context = f"Block '{node_name}' ({node_type})"

                # Rule: PII Disclosure
                pii_hits = SecurityRules.check_pii_disclosure(node_str, context)
                for hit in pii_hits:
                    issues.append(Issue(file_path, "PII Leakage", hit, "Medium"))

                # Rule: Dangerous Python Code
                if node_type == 'code':
                    py_code = node_data.get('code', '')
                    code_hits = SecurityRules.check_dangerous_code(py_code, "python", context)
                    for hit in code_hits:
                        issues.append(Issue(file_path, "Dangerous Code", hit, "High"))

        except Exception as e:
            print(f"DEBUG: Error parsing Dify file {file_path}: {e}")
            
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
                        self.stats.files_with_issues += 1
                        for i in file_issues:
                            self.stats.issue_distribution[i.severity] += 1
                except Exception as e:
                    self.stats.error_count += 1
                    print(f"Error scanning {file_path}: {e}")
            else:
                # print(f"Skipping unsupported file: {file_path}")
                pass

        return all_issues