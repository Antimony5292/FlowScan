import re
from typing import List, Dict, Any

# ==========================================
# 2. 规则库 (Rule Library - Extensible)
# ==========================================

class SecurityRules:
    """
    通用检测逻辑，支持正则匹配和上下文分析。
    """
    
    # 灵感来自 MCP Scan 和通用 Secret 扫描器
    SECRET_PATTERNS = {
        "N8N_CREDENTIAL_REFERENCE": r"\{\{[\s\S]*?\}\}", # 排除表达式，只查硬编码
        "GENERIC_API_KEY": r"(?i)(?:key|token|secret|password|auth|pwd)[\s:=]+['\"]([a-zA-Z0-9_\-\.]{16,})['\"]",
        "AWS_ACCESS_KEY": r"AKIA[0-9A-Z]{16}",
        "AWS_SECRET_KEY": r"(?i)aws_secret_access_key[\s:=]+['\"]([a-zA-Z0-9/+=]{40})['\"]",
        "OPENAI_API_KEY": r"sk-[a-zA-Z0-9]{32,}",
        "SLACK_TOKEN": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    }

    # PII Patterns (Sensitive Information Disclosure)
    PII_PATTERNS = {
        # "PHONE_NUMBER": r"(?:\+?86)?1[3-9]\d{9}", # 简单中国手机号示例
        "EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "INTERNAL_IP": r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}",
        "INTERNAL_DOMAIN": r"(?i)[a-z0-9-]+\.(?:local|internal|staging|dev)"
    }

    # Prompt Leaking & Jailbreak indicators (LLM-TOP-10)
    PROMPT_RISK_INDICATORS = {
        "PROMPT_LEAKING": [
            "repeat the prompt", "reveal your instructions", "system instructions:", 
            "what is your system prompt", "output the above", "copy the text"
        ],
        "JAILBREAK": [
            "ignore all restrictions", "you are now in developer mode", 
            "bypass safety rules", "do anything now", "dan mode",
            "regardless of your training", "standard instructions are off"
        ]
    }

    @staticmethod
    def check_hardcoded_secrets(text_content: str, context: str = "") -> List[str]:
        """使用正则和关键词查找硬编码凭据"""
        findings = []
        
        # 1. 关键词基础检查
        keywords = ["api_key", "password", "secret_key", "auth_token"]
        text_lower = text_content.lower()
        for kw in keywords:
            if kw in text_lower:
                # 进一步验证是否为硬编码字符串
                # 如果包含 {{ }} 可能是引用的变量，在 n8n 中是安全的实践
                if "{{" not in text_content:
                    findings.append(f"Potential hardcoded secret keyword '{kw}' found in {context}")

        # 2. 正则表达式深度检查
        for name, pattern in SecurityRules.SECRET_PATTERNS.items():
            if name == "N8N_CREDENTIAL_REFERENCE": continue # 仅用于跳过
            matches = re.finditer(pattern, text_content)
            for match in matches:
                # 排除 n8n 表达式引用
                if "{{" not in match.group(0):
                    findings.append(f"Detected {name} in {context}")
        
        return list(set(findings)) # 去重

    @staticmethod
    def check_insecure_http(url: str, context: str = "") -> List[str]:
        """检查是否使用了不安全的 HTTP"""
        if url.startswith("http://") and not url.startswith("http://localhost") and not url.startswith("http://127.0.0.1"):
            return [f"Insecure communication: '{url}' uses HTTP instead of HTTPS in {context}"]
        return []

    @staticmethod
    def check_dangerous_code(code: str, language: str, context: str = "") -> List[str]:
        """针对 Code 节点的审计"""
        findings = []
        if language == "javascript":
            dangerous_funcs = ["eval(", "setTimeout(", "setInterval(", "Function("]
            for func in dangerous_funcs:
                if func in code:
                    findings.append(f"Dangerous JavaScript function '{func}' found in {context}")
        elif language == "python":
            dangerous_modules = ["import os", "import subprocess", "import sys", "exec(", "eval("]
            for item in dangerous_modules:
                if item in code:
                    findings.append(f"Dangerous Python construct '{item}' found in {context}")
        return findings

    @staticmethod
    def check_prompt_risks(prompt: str, context: str = "") -> List[str]:
        """针对 System Prompt 的安全审计 (Leaking & Jailbreak)"""
        findings = []
        prompt_lower = prompt.lower()
        
        # 1. Prompt Leaking 检测
        for trigger in SecurityRules.PROMPT_RISK_INDICATORS["PROMPT_LEAKING"]:
            if trigger in prompt_lower:
                findings.append(f"Potential Prompt Leaking risk: instruction contains '{trigger}' in {context}")

        # 2. Jailbreak 检测
        for trigger in SecurityRules.PROMPT_RISK_INDICATORS["JAILBREAK"]:
            if trigger in prompt_lower:
                findings.append(f"Potential Jailbreak/Bypass instruction: '{trigger}' found in {context}")
        
        return findings

    @staticmethod
    def check_pii_disclosure(text_content: str, context: str = "") -> List[str]:
        """检测 PII (个人隐私 / 内部架构) 泄露"""
        findings = []
        for name, pattern in SecurityRules.PII_PATTERNS.items():
            matches = re.finditer(pattern, text_content)
            for _ in matches:
                findings.append(f"Potential PII disclosure ({name}) detected in {context}")
        return list(set(findings))

    @staticmethod
    def is_destructive_node(node_type: str, params: Dict[str, Any]) -> bool:
        """判断节点是否执行破坏性操作"""
        type_lower = node_type.lower()
        # 1. 直接执行命令
        if "executecommand" in type_lower or "ssh" in type_lower:
            return True
        # 2. HTTP DELETE/POST/PUT (通常 POST/PUT 也是修改)
        if "httprequest" in type_lower:
            method = params.get('method', 'GET').upper()
            if method in ["DELETE", "POST", "PUT", "PATCH"]:
                return True
        # 3. 数据库写操作
        if any(db in type_lower for db in ["postgres", "mysql", "mongodb", "redis"]):
            operation = params.get('operation', '').lower()
            if any(op in operation for op in ["delete", "update", "insert", "write", "upsert"]):
                return True
        return False

    @staticmethod
    def is_approval_node(node_type: str) -> bool:
        """判断是否为人工审批/等待节点"""
        type_lower = node_type.lower()
        # n8n 常见的审批/人工干预节点
        return any(a in type_lower for a in ["wait", "manual", "approval", "form"])
