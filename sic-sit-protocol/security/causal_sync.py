"""
SIC-SIT Constitutional Governance Layer
Module: CausalEntropySync
Version: 1.0.0
Constitution: SIC-CONSTITUTION v1.1.3

This module is part of the SIC-SIT protocol.
See CONSTITUTION.json for governance rules.
"""

from typing import Dict, List, Any

class CausalEntropySync:
    """
    因果時間戳同步
    """
    
    def __init__(self):
        self.local_clock = 0
        self.vector_clocks = {}
    
    def tick(self) -> int:
        self.local_clock += 1
        return self.local_clock
    
    def send_event(self, node_id: str) -> Dict[str, Any]:
        self.tick()
        return {
            "node_id": node_id,
            "lamport_timestamp": self.local_clock,
            "vector_clock": self.vector_clocks.copy()
        }
    
    def receive_event(self, remote_timestamp: int, remote_node_id: str):
        self.local_clock = max(self.local_clock, remote_timestamp) + 1
        self.vector_clocks[remote_node_id] = remote_timestamp
    
    def happens_before(self, event_a: Dict[str, Any], event_b: Dict[str, Any]) -> bool:
        return event_a.get("lamport_timestamp", 0) < event_b.get("lamport_timestamp", 0)
    
    def get_causal_order(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return sorted(events, key=lambda e: e.get("lamport_timestamp", 0))
