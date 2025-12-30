"""
SIC-SIT Constitutional Governance Layer
Module: EntropyFusion
Version: 1.0.0
Constitution: SIC-CONSTITUTION v1.1.3

This module is part of the SIC-SIT protocol.
See CONSTITUTION.json for governance rules.
"""

import hashlib
import secrets
import time
from typing import Dict, List, Any

class EntropyFusion:
    """
    三源熵融合模組
    """
    
    def __init__(self, db):
        self.db = db
        self.entropy_pool = []
    
    def fuse_entropy(self, semantic_data: str = "") -> str:
        system_entropy = secrets.token_hex(32)
        time_entropy = str(time.time_ns())
        semantic_entropy = hashlib.sha256(semantic_data.encode()).hexdigest()
        fused_raw = f"{system_entropy}{time_entropy}{semantic_entropy}"
        fused_hash = hashlib.sha256(fused_raw.encode()).hexdigest()
        self.entropy_pool.append({
            "hash": fused_hash,
            "timestamp": time.time(),
            "sources": ["system", "time", "semantic"]
        })
        if len(self.entropy_pool) > 100:
            self.entropy_pool.pop(0)
        return fused_hash
    
    def check_independence(self) -> Dict[str, Any]:
        if len(self.entropy_pool) < 2:
            return {"independence_score": 1.0, "warning": False}
        h1 = self.entropy_pool[-1]["hash"]
        h2 = self.entropy_pool[-2]["hash"]
        diff_count = sum(1 for c1, c2 in zip(h1, h2) if c1 != c2)
        independence_score = diff_count / len(h1)
        return {
            "independence_score": independence_score,
            "warning": independence_score < 0.9,
            "message": "熵源獨立性不足" if independence_score < 0.9 else "熵源獨立性正常"
        }
