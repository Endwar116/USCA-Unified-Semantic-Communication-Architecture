"""
SIC-SIT Constitutional Governance Layer
Module: SWATProtocol
Version: 1.0.0
Constitution: SIC-CONSTITUTION v1.1.3

This module is part of the SIC-SIT protocol.
See CONSTITUTION.json for governance rules.
"""

import numpy as np
from typing import List, Dict, Any

class SWATProtocol:
    """
    Semantic-Weighted Adaptive Threshold
    """
    
    def __init__(self, db):
        self.db = db
        self.base_difficulty = 1.0
        self.max_stake_discount = 0.5
        self.resource_tiers = {
            "tier_1_edge": {"difficulty_multiplier": 0.5, "weight_multiplier": 0.8},
            "tier_2_standard": {"difficulty_multiplier": 1.0, "weight_multiplier": 1.0},
            "tier_3_heavy": {"difficulty_multiplier": 1.5, "weight_multiplier": 1.1}
        }
    
    def calculate_novelty_score(self, intent_vector: List[float], existing_vectors: List[List[float]]) -> float:
        if not existing_vectors:
            return 1.0
        max_similarity = 0
        for existing in existing_vectors:
            similarity = self._cosine_similarity(intent_vector, existing)
            max_similarity = max(max_similarity, similarity)
        return 1.0 - max_similarity
    
    def calculate_effective_difficulty(self, network_load: float, novelty_score: float, reputation_stake: float, resource_tier: str) -> float:
        tier_config = self.resource_tiers.get(resource_tier, self.resource_tiers["tier_2_standard"])
        difficulty = self.base_difficulty * (1 + network_load) / (1 + novelty_score)
        difficulty *= tier_config["difficulty_multiplier"]
        stake_discount = min(self.max_stake_discount, reputation_stake / 100.0)
        difficulty *= (1 - stake_discount)
        return max(0.1, difficulty)
    
    def check_fairness(self, node_stats: Dict[str, float]) -> Dict[str, Any]:
        if not node_stats:
            return {"max_single_share": 0, "fairness_violated": False}
        total_weight = sum(node_stats.values())
        if total_weight == 0:
            return {"max_single_share": 0, "fairness_violated": False}
        max_share = max(node_stats.values()) / total_weight
        sorted_weights = sorted(node_stats.values(), reverse=True)
        top_10_percent_count = max(1, len(sorted_weights) // 10)
        top_10_percent_weight = sum(sorted_weights[:top_10_percent_count]) / total_weight
        return {
            "max_single_share": max_share,
            "top_10_percent_share": top_10_percent_weight,
            "fairness_violated": max_share > 0.15 or top_10_percent_weight > 0.5,
            "recommended_action": "REDISTRIBUTE" if max_share > 0.15 else None
        }
    
    def _cosine_similarity(self, v1: List[float], v2: List[float]) -> float:
        vec1 = np.array(v1, dtype=np.float32)
        vec2 = np.array(v2, dtype=np.float32)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        if norm1 == 0 or norm2 == 0:
            return 0.0
        return float(np.dot(vec1, vec2) / (norm1 * norm2))
