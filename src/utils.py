import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Any, Type
from collections import defaultdict
# ==========================================
# 1. 基础数据结构 (Data Structures)
# ==========================================

@dataclass
class Issue:
    """定义一个通用的安全问题结构"""
    file_path: str
    issue_type: str
    detail: str
    severity: str = "Medium" # High, Medium, Low

@dataclass
class ScanStats:
    start_time: str = field(default_factory=lambda: datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    scanned_count: int = 0
    issue_count: int = 0
    error_count: int = 0
    files_with_issues: int = 0
    issue_distribution: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
