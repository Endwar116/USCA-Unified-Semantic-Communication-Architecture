"""
SIC-SIT Constitutional Governance Layer
Module: ConstitutionLayer
Version: 1.0.0
Constitution: SIC-CONSTITUTION v1.1.3

This module is part of the SIC-SIT protocol.
See CONSTITUTION.json for governance rules.
"""

import json
from datetime import datetime
from typing import Dict, List, Any

class ConstitutionLayer:
    """
    SIC-CONSTITUTION v1.1.3 執行層
    所有操作必須通過公理檢查
    """
    
    def __init__(self, db):
        self.db = db
        self.overflow_buffer = []
        
        # 定義公理
        self.AXIOMS = {
            "A1": {
                "statement": "所有安全漏洞都是邊界故障",
                "check": lambda ctx: ctx.get("boundary_defined", False),
                "on_violation": "REJECT_AND_LOG"
            },
            "A2": {
                "statement": "AI 原生系統的邊界是語義意圖，不是數據",
                "check": lambda ctx: ctx.get("is_semantic_intent", False),
                "on_violation": "TRANSFORM_TO_INTENT"
            },
            "A3": {
                "statement": "結構化語義狀態本質上是被消毒的",
                "check": lambda ctx: ctx.get("is_structured", False),
                "on_violation": "SANITIZE"
            },
            "A4": {
                "statement": "AI 不預言、不決定、不取代意志",
                "check": lambda ctx: not ctx.get("replaces_human_will", False),
                "on_violation": "HALT_AND_ESCALATE",
                "priority": "HIGHEST"
            },
            "A5": {
                "statement": "溢出是信號，不是錯誤",
                "check": lambda ctx: True,  # Always capture overflow
                "on_overflow": "CAPTURE_AND_ANALYZE"
            },
            "A6": {
                "statement": "量化即共識",
                "check": lambda ctx: ctx.get("is_quantifiable", False),
                "on_violation": "REQUEST_QUANTIFICATION"
            },
            "A7": {
                "statement": "語義一致性是跨模型協作的唯一基礎",
                "check": lambda ctx: ctx.get("semantic_consistent", False),
                "on_violation": "REALIGN_SEMANTICS"
            },
            "A8": {
                "statement": "時間拓撲是語義密度的第四維度",
                "check": lambda ctx: ctx.get("has_temporal_marker", False),
                "on_violation": "ADD_TEMPORAL_MARKER"
            },
            "A9": {
                "statement": "格式是協議的邊界，不可被內容價值覆寫",
                "check": lambda ctx: ctx.get("format_compliant", False),
                "on_violation": "REJECT_REFORMAT"
            },
            "A10": {
                "statement": "不信任數據，信任結構",
                "check": lambda ctx: ctx.get("structure_verified", False),
                "on_violation": "VERIFY_STRUCTURE"
            },
            "A11": {
                "statement": "不信任節點，信任網絡",
                "check": lambda ctx: ctx.get("network_consensus", False),
                "on_violation": "REQUIRE_CONSENSUS"
            },
            "A12": {
                "statement": "預測即脆弱，混沌即堅固",
                "check": lambda ctx: ctx.get("entropy_sufficient", False),
                "on_violation": "INJECT_ENTROPY"
            },
            "A13": {
                "statement": "分佈式系統沒有『現在』，只有因果順序",
                "check": lambda ctx: ctx.get("has_causal_order", False),
                "on_violation": "ADD_LAMPORT_TIMESTAMP"
            },
            "A14": {
                "statement": "誠實節點可被誤判，惡意節點可偽裝誠實",
                "check": lambda ctx: ctx.get("signature_verified", False),
                "on_violation": "REQUIRE_SIGNATURE"
            },
            "A15": {
                "statement": "治理複雜度存在相變臨界點",
                "check": lambda ctx: ctx.get("complexity_score", 0) < 4.0,
                "on_violation": "TRIGGER_COMPRESSION"
            },
            "A16": {
                "statement": "安全機制不得以犧牲參與公平性為代價",
                "check": lambda ctx: ctx.get("fairness_score", 0) > 0.5,
                "on_violation": "APPLY_SWAT"
            },
            "A17": {
                "statement": "語義價值優先於計算資源",
                "check": lambda ctx: True,  # Always apply semantic weighting
                "modifier": "APPLY_NOVELTY_BONUS"
            }
        }
    
    def validate_operation(self, operation_type: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        驗證操作是否符合所有公理
        """
        violations = []
        actions = []
        
        for axiom_id, axiom in self.AXIOMS.items():
            if not axiom["check"](context):
                violation = {
                    "axiom": axiom_id,
                    "statement": axiom["statement"],
                    "action": axiom.get("on_violation", "LOG")
                }
                violations.append(violation)
                actions.append(axiom.get("on_violation", "LOG"))
                self._log_violation(axiom_id, operation_type, context, axiom.get("on_violation", "LOG"))
        
        if any(v["axiom"] == "A4" for v in violations):
            return {
                "valid": False,
                "violations": violations,
                "actions": ["HALT_AND_ESCALATE"],
                "message": "違反 A4：AI 不取代意志。操作已停止。"
            }
        
        return {
            "valid": len(violations) == 0,
            "violations": violations,
            "actions": actions
        }
    
    def _log_violation(self, axiom_id: str, op_type: str, context: dict, action: str):
        cursor = self.db.conn.cursor()
        cursor.execute("""
            INSERT INTO axiom_violations (axiom_id, operation_type, context, action_taken)
            VALUES (?, ?, ?, ?)
        """, (axiom_id, op_type, json.dumps(context), action))
        self.db.conn.commit()

    def capture_overflow(self, content: Dict[str, Any], source_model: str = None):
        overflow_entry = {
            "timestamp": datetime.now().isoformat(),
            "content": content,
            "source_model": source_model,
            "status": "CAPTURED"
        }
        self.overflow_buffer.append(overflow_entry)
        cursor = self.db.conn.cursor()
        cursor.execute("""
            INSERT INTO overflow_captures (content, source_model, status)
            VALUES (?, ?, ?)
        """, (json.dumps(content), source_model, "CAPTURED"))
        self.db.conn.commit()
    
    def get_overflow_insights(self) -> List[Dict[str, Any]]:
        return self.overflow_buffer
