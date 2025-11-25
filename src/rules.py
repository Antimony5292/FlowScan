from typing import List, Dict, Any, Type

# ==========================================
# 2. 规则库 (Rule Library - Extensible)
# ==========================================

class SecurityRules:
    """
    这里存放通用的检测逻辑。
    可以将具体的检测逻辑拆分到不同的函数中，方便复用。
    """
    
    @staticmethod
    def check_hardcoded_secrets(text_content: str, key_context: str = "") -> List[str]:
        """通用文本检测：查找敏感词"""
        secrets = []
        keywords = ["api_key", "sk-", "password", "secret_key"]
        text_lower = text_content.lower()
        
        for kw in keywords:
            if kw in text_lower:
                secrets.append(f"Found potential secret keyword '{kw}' in {key_context}")
        return secrets

    @staticmethod
    def check_prompt_injection(node_type: str, node_content: str) -> List[str]:
        """针对AI/HTTP节点的注入检测"""
        risks = []
        # 假设这是一些容易受注入的节点类型
        risky_types = ["httpRequest", "chatGPT", "llm", "code"]
        
        is_risky = any(rt in node_type for rt in risky_types)
        if is_risky and "webhook" in node_content.lower():
             risks.append(f"Node type '{node_type}' accepts direct Webhook input without visible sanitization.")
        return risks
