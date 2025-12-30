"""
SIC-SIT Constitutional Governance Layer
Module: ByzantineFaultTolerance
Version: 1.0.0
Constitution: SIC-CONSTITUTION v1.1.3

This module is part of the SIC-SIT protocol.
See CONSTITUTION.json for governance rules.
"""

import uuid
from typing import Dict, List, Any

class ByzantineFaultTolerance:
    """
    拜占庭容錯模組
    """
    
    def __init__(self, db, threshold: float = 0.33):
        self.db = db
        self.threshold = threshold
        self.node_trust_scores = {}
    
    def update_node_trust(self, node_id: str, is_honest: bool):
        current_score = self.node_trust_scores.get(node_id, 1.0)
        if is_honest:
            new_score = min(1.0, current_score + 0.05)
        else:
            new_score = max(0.0, current_score - 0.4)
        
        self.node_trust_scores[node_id] = new_score
        self.db.log_audit(
            audit_id=f"audit_{uuid.uuid4().hex[:12]}",
            action="TRUST_UPDATE",
            model_name=node_id,
            details=f"Trust score updated to {new_score:.2f} (Honest: {is_honest})"
        )
    
    def check_byzantine_ratio(self) -> Dict[str, Any]:
        if not self.node_trust_scores:
            return {"ratio": 0.0, "safe": True, "total_nodes": 0}
            
        total_nodes = len(self.node_trust_scores)
        byzantine_nodes = [nid for nid, score in self.node_trust_scores.items() if score < 0.5]
        ratio = len(byzantine_nodes) / total_nodes
        is_safe = ratio < self.threshold
        
        if not is_safe:
            self.db.log_audit(
                audit_id=f"audit_{uuid.uuid4().hex[:12]}",
                action="GOVERNANCE_OVERFLOW",
                details=f"Byzantine ratio {ratio:.2%} exceeded threshold {self.threshold:.2%}"
            )
            
        return {
            "ratio": ratio,
            "byzantine_count": len(byzantine_nodes),
            "total_nodes": total_nodes,
            "safe": is_safe,
            "action_required": "GOVERNANCE_OVERFLOW" if not is_safe else None
        }
    
    def get_consensus_weight(self, node_id: str) -> float:
        return self.node_trust_scores.get(node_id, 1.0)
