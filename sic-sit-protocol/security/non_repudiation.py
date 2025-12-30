"""
SIC-SIT Constitutional Governance Layer
Module: NonRepudiationChain
Version: 1.0.0
Constitution: SIC-CONSTITUTION v1.1.3

This module is part of the SIC-SIT protocol.
See CONSTITUTION.json for governance rules.
"""

import hashlib
import json
import secrets
from datetime import datetime
from typing import Dict, List, Any

class NonRepudiationChain:
    """
    不可否認簽名鏈
    """
    
    def __init__(self, db):
        self.db = db
        self.node_keys = {}
    
    def generate_keypair(self, node_id: str) -> Dict[str, str]:
        private_key = secrets.token_hex(32)
        public_key = hashlib.sha256(private_key.encode()).hexdigest()
        self.node_keys[node_id] = {"public": public_key, "private": private_key}
        return {"node_id": node_id, "public_key": public_key}
    
    def sign_stc(self, node_id: str, stc: Dict[str, Any]) -> Dict[str, Any]:
        if node_id not in self.node_keys:
            self.generate_keypair(node_id)
        stc_content = json.dumps(stc, sort_keys=True, default=str)
        stc_hash = hashlib.sha256(stc_content.encode()).hexdigest()
        private_key = self.node_keys[node_id]["private"]
        signature = hashlib.sha256(f"{stc_hash}{private_key}".encode()).hexdigest()
        return {
            "stc_hash": stc_hash,
            "signature": signature,
            "signer": node_id,
            "public_key": self.node_keys[node_id]["public"],
            "timestamp": datetime.now().isoformat()
        }
    
    def verify_signature(self, stc: Dict[str, Any], signature_data: Dict[str, Any]) -> bool:
        node_id = signature_data["signer"]
        if node_id not in self.node_keys:
            return False
        stc_content = json.dumps(stc, sort_keys=True, default=str)
        stc_hash = hashlib.sha256(stc_content.encode()).hexdigest()
        private_key = self.node_keys[node_id]["private"]
        expected_signature = hashlib.sha256(f"{stc_hash}{private_key}".encode()).hexdigest()
        return signature_data["signature"] == expected_signature
    
    def create_proof_chain(self, stc: Dict[str, Any], signers: List[str]) -> Dict[str, Any]:
        signatures = []
        for signer in signers:
            sig = self.sign_stc(signer, stc)
            signatures.append(sig)
        return {
            "stc_id": stc.get("id"),
            "proof_chain": signatures,
            "chain_length": len(signatures),
            "created_at": datetime.now().isoformat()
        }
