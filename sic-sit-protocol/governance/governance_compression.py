"""
SIC-SIT Constitutional Governance Layer
Module: GovernanceCompression
Version: 1.0.0
Constitution: SIC-CONSTITUTION v1.1.3

This module is part of the SIC-SIT protocol.
See CONSTITUTION.json for governance rules.
"""

import math
import hashlib
import json
from datetime import datetime
from typing import Dict, List, Any

class GovernanceCompression:
    """
    治理壓縮引擎
    """
    
    def __init__(self, db, complexity_threshold: float = 4.0, node_threshold: int = 20):
        self.db = db
        self.complexity_threshold = complexity_threshold
        self.node_threshold = node_threshold
    
    def calculate_complexity(self, node_count: int, byzantine_ratio: float, trust_variance: float) -> float:
        """
        計算治理複雜度
        """
        return math.log(node_count + 1) * (1 + byzantine_ratio) * (1 + trust_variance)
    
    def should_compress(self, node_count: int, complexity_score: float) -> bool:
        return node_count > self.node_threshold or complexity_score > self.complexity_threshold
    
    def generate_compressed_summary(self, governance_state: Dict[str, Any]) -> Dict[str, Any]:
        node_count = governance_state.get("node_count", 0)
        complexity_score = governance_state.get("complexity_score", 0)
        
        summary = {
            "summary": f"治理狀態摘要 — {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "key_metrics": {
                "total_nodes": node_count,
                "complexity_score": round(complexity_score, 2),
                "byzantine_ratio": f"{governance_state.get('byzantine_ratio', 0) * 100:.1f}%",
                "phase": self._determine_phase(node_count)
            },
            "alerts": governance_state.get("alerts", []),
            "compressed": True,
            "timestamp": datetime.now().isoformat()
        }
        
        self._save_snapshot(governance_state)
        return summary
    
    def _determine_phase(self, node_count: int) -> str:
        if node_count < 7:
            return "phase_1_human_readable"
        elif node_count <= 20:
            return "phase_2_tool_assisted"
        else:
            return "phase_3_compressed"
            
    def _save_snapshot(self, state: Dict[str, Any]):
        snapshot_data = json.dumps(state, sort_keys=True)
        snapshot_hash = hashlib.sha256(snapshot_data.encode()).hexdigest()
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO governance_snapshots (snapshot_hash, node_count, complexity_score, byzantine_ratio)
                VALUES (?, ?, ?, ?)
            """, (
                snapshot_hash,
                state.get("node_count", 0),
                state.get("complexity_score", 0),
                state.get("byzantine_ratio", 0)
            ))
            self.db.conn.commit()
        except Exception:
            pass
