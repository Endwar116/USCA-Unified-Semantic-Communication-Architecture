"""
SIT Handshake — Semantic Isolation Transfer 三次握手協議

USCA 協議棧位置: L3 (Transport Layer)
類比: TCP 三次握手，但建立的是「語義共識」而非「連接」

握手流程:
1. SIT-SYN:     請求者宣告語義上下文範圍
2. SIT-SYN-ACK: 接收者回覆語義邊界與預期
3. SIT-ACK:     雙方進入共享語義模式

設計來源: 老翔 USCA 規格
實作: Claude (尾德) Round 10+
日期: 2025-12-29
版本: 1.0.0
"""

import uuid
import hashlib
import hmac
import json
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class SIT_HandshakeState(Enum):
    """握手狀態"""
    INIT = "INIT"               # 初始狀態
    SYN_SENT = "SYN_SENT"       # 已發送 SYN
    SYN_RECEIVED = "SYN_RECEIVED"  # 已收到 SYN
    ESTABLISHED = "ESTABLISHED"  # 已建立
    FAILED = "FAILED"           # 失敗
    TIMEOUT = "TIMEOUT"         # 超時


class SIT_HandshakeError(Enum):
    """握手錯誤碼"""
    OK = "SIT-HS-000"
    SCOPE_MISMATCH = "SIT-HS-001"       # 範圍不匹配
    CONSTRAINT_CONFLICT = "SIT-HS-002"  # 約束衝突
    SIGNATURE_INVALID = "SIT-HS-003"    # 簽名無效
    TIMEOUT = "SIT-HS-004"              # 超時
    REQUESTER_DENIED = "SIT-HS-005"     # 請求者被拒絕
    SEMANTIC_INCOMPATIBLE = "SIT-HS-006"  # 語義不兼容


@dataclass
class SIT_SYN:
    """
    SIT-SYN 封包
    
    第一步：請求者宣告語義上下文範圍
    """
    # 必填
    session_id: str
    requester_id: str
    intent_scope: str           # 意圖範圍描述
    semantic_boundary: Dict     # 語義邊界定義
    
    # 約束
    constraints: Dict = field(default_factory=dict)
    
    # 元數據
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    ttl_seconds: int = 30       # 握手超時時間
    
    # 簽名
    signature: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "type": "SIT-SYN",
            "session_id": self.session_id,
            "requester_id": self.requester_id,
            "intent_scope": self.intent_scope,
            "semantic_boundary": self.semantic_boundary,
            "constraints": self.constraints,
            "timestamp": self.timestamp,
            "ttl_seconds": self.ttl_seconds,
            "signature": self.signature
        }


@dataclass
class SIT_SYN_ACK:
    """
    SIT-SYN-ACK 封包
    
    第二步：接收者回覆語義邊界與預期
    """
    # 關聯
    session_id: str
    syn_signature: str          # 對應 SYN 的簽名
    
    # 回覆
    responder_id: str
    accepted_scope: str         # 接受的範圍
    constraints_accepted: Dict  # 接受的約束
    constraints_modified: Dict  # 修改的約束
    
    # 會話令牌
    session_token: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    # 元數據
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    
    # 簽名
    signature: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "type": "SIT-SYN-ACK",
            "session_id": self.session_id,
            "syn_signature": self.syn_signature,
            "responder_id": self.responder_id,
            "accepted_scope": self.accepted_scope,
            "constraints_accepted": self.constraints_accepted,
            "constraints_modified": self.constraints_modified,
            "session_token": self.session_token,
            "timestamp": self.timestamp,
            "signature": self.signature
        }


@dataclass
class SIT_ACK:
    """
    SIT-ACK 封包
    
    第三步：確認進入共享語義模式
    """
    # 關聯
    session_id: str
    session_token: str
    syn_ack_signature: str      # 對應 SYN-ACK 的簽名
    
    # 確認
    confirmed: bool
    semantic_mode: str          # 共享語義模式標識
    
    # 元數據
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    
    # 簽名
    signature: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "type": "SIT-ACK",
            "session_id": self.session_id,
            "session_token": self.session_token,
            "syn_ack_signature": self.syn_ack_signature,
            "confirmed": self.confirmed,
            "semantic_mode": self.semantic_mode,
            "timestamp": self.timestamp,
            "signature": self.signature
        }


@dataclass
class SIT_Session:
    """
    SIT 會話
    
    握手成功後建立的語義共享會話
    """
    session_id: str
    session_token: str
    requester_id: str
    responder_id: str
    
    # 協商結果
    agreed_scope: str
    agreed_constraints: Dict
    semantic_mode: str
    
    # 狀態
    state: SIT_HandshakeState
    established_at: str
    expires_at: str
    
    # 簽名鏈
    signature_chain: list = field(default_factory=list)


class SIT_Handshake:
    """
    SIT 三次握手協議實作
    
    提供完整的握手流程管理，包括：
    - SYN/SYN-ACK/ACK 封包處理
    - 簽名驗證
    - 超時處理
    - 會話建立
    """
    
    def __init__(self, secret_key: str, entity_id: str):
        """
        初始化握手管理器
        
        Args:
            secret_key: HMAC 簽名密鑰
            entity_id: 本實體 ID（用於識別請求者/接收者）
        """
        self.secret_key = secret_key.encode('utf-8')
        self.entity_id = entity_id
        self.pending_sessions: Dict[str, Dict] = {}  # session_id -> state
        self.established_sessions: Dict[str, SIT_Session] = {}
    
    # ========== 請求者端 ==========
    
    def create_syn(
        self,
        intent_scope: str,
        semantic_boundary: Dict,
        constraints: Optional[Dict] = None
    ) -> SIT_SYN:
        """
        建立 SIT-SYN 封包（請求者調用）
        
        Args:
            intent_scope: 意圖範圍描述
            semantic_boundary: 語義邊界定義
            constraints: 約束條件
        
        Returns:
            SIT_SYN 封包
        """
        session_id = str(uuid.uuid4())
        
        syn = SIT_SYN(
            session_id=session_id,
            requester_id=self.entity_id,
            intent_scope=intent_scope,
            semantic_boundary=semantic_boundary,
            constraints=constraints or {}
        )
        
        # 簽名
        syn.signature = self._sign(syn.to_dict())
        
        # 記錄待處理會話
        self.pending_sessions[session_id] = {
            "state": SIT_HandshakeState.SYN_SENT,
            "syn": syn,
            "created_at": datetime.utcnow()
        }
        
        return syn
    
    def process_syn_ack(self, syn_ack: SIT_SYN_ACK) -> Tuple[Optional[SIT_ACK], Optional[SIT_HandshakeError]]:
        """
        處理 SIT-SYN-ACK 並回覆 SIT-ACK（請求者調用）
        
        Args:
            syn_ack: 收到的 SYN-ACK 封包
        
        Returns:
            (SIT_ACK, None) 成功
            (None, error) 失敗
        """
        session_id = syn_ack.session_id
        
        # 檢查會話是否存在
        if session_id not in self.pending_sessions:
            return None, SIT_HandshakeError.SCOPE_MISMATCH
        
        pending = self.pending_sessions[session_id]
        
        # 驗證 SYN-ACK 簽名
        if not self._verify_signature(syn_ack.to_dict(), syn_ack.signature):
            return None, SIT_HandshakeError.SIGNATURE_INVALID
        
        # 驗證 SYN 簽名對應
        if syn_ack.syn_signature != pending["syn"].signature:
            return None, SIT_HandshakeError.SIGNATURE_INVALID
        
        # 檢查超時
        if self._is_timeout(pending["created_at"], pending["syn"].ttl_seconds):
            self.pending_sessions.pop(session_id, None)
            return None, SIT_HandshakeError.TIMEOUT
        
        # 建立 ACK
        ack = SIT_ACK(
            session_id=session_id,
            session_token=syn_ack.session_token,
            syn_ack_signature=syn_ack.signature,
            confirmed=True,
            semantic_mode=f"shared-{session_id[:8]}"
        )
        ack.signature = self._sign(ack.to_dict())
        
        # 建立會話
        session = SIT_Session(
            session_id=session_id,
            session_token=syn_ack.session_token,
            requester_id=self.entity_id,
            responder_id=syn_ack.responder_id,
            agreed_scope=syn_ack.accepted_scope,
            agreed_constraints={
                **syn_ack.constraints_accepted,
                **syn_ack.constraints_modified
            },
            semantic_mode=ack.semantic_mode,
            state=SIT_HandshakeState.ESTABLISHED,
            established_at=datetime.utcnow().isoformat() + "Z",
            expires_at=(datetime.utcnow() + timedelta(hours=1)).isoformat() + "Z",
            signature_chain=[
                pending["syn"].signature,
                syn_ack.signature,
                ack.signature
            ]
        )
        
        self.established_sessions[session_id] = session
        self.pending_sessions.pop(session_id, None)
        
        return ack, None
    
    # ========== 接收者端 ==========
    
    def process_syn(
        self,
        syn: SIT_SYN,
        accept: bool = True,
        modified_constraints: Optional[Dict] = None
    ) -> Tuple[Optional[SIT_SYN_ACK], Optional[SIT_HandshakeError]]:
        """
        處理 SIT-SYN 並回覆 SIT-SYN-ACK（接收者調用）
        
        Args:
            syn: 收到的 SYN 封包
            accept: 是否接受
            modified_constraints: 修改的約束
        
        Returns:
            (SIT_SYN_ACK, None) 成功
            (None, error) 失敗
        """
        # 驗證簽名
        if not self._verify_signature(syn.to_dict(), syn.signature):
            return None, SIT_HandshakeError.SIGNATURE_INVALID
        
        # 檢查超時
        try:
            syn_time = datetime.fromisoformat(syn.timestamp.replace('Z', '+00:00'))
            if self._is_timeout(syn_time, syn.ttl_seconds):
                return None, SIT_HandshakeError.TIMEOUT
        except:
            pass
        
        if not accept:
            return None, SIT_HandshakeError.REQUESTER_DENIED
        
        # 建立 SYN-ACK
        syn_ack = SIT_SYN_ACK(
            session_id=syn.session_id,
            syn_signature=syn.signature,
            responder_id=self.entity_id,
            accepted_scope=syn.intent_scope,
            constraints_accepted=syn.constraints,
            constraints_modified=modified_constraints or {}
        )
        syn_ack.signature = self._sign(syn_ack.to_dict())
        
        # 記錄待處理會話
        self.pending_sessions[syn.session_id] = {
            "state": SIT_HandshakeState.SYN_RECEIVED,
            "syn": syn,
            "syn_ack": syn_ack,
            "created_at": datetime.utcnow()
        }
        
        return syn_ack, None
    
    def process_ack(self, ack: SIT_ACK) -> Tuple[Optional[SIT_Session], Optional[SIT_HandshakeError]]:
        """
        處理 SIT-ACK 並建立會話（接收者調用）
        
        Args:
            ack: 收到的 ACK 封包
        
        Returns:
            (SIT_Session, None) 成功
            (None, error) 失敗
        """
        session_id = ack.session_id
        
        if session_id not in self.pending_sessions:
            return None, SIT_HandshakeError.SCOPE_MISMATCH
        
        pending = self.pending_sessions[session_id]
        
        # 驗證簽名
        if not self._verify_signature(ack.to_dict(), ack.signature):
            return None, SIT_HandshakeError.SIGNATURE_INVALID
        
        # 驗證 SYN-ACK 簽名對應
        if ack.syn_ack_signature != pending["syn_ack"].signature:
            return None, SIT_HandshakeError.SIGNATURE_INVALID
        
        # 驗證會話令牌
        if ack.session_token != pending["syn_ack"].session_token:
            return None, SIT_HandshakeError.SCOPE_MISMATCH
        
        if not ack.confirmed:
            return None, SIT_HandshakeError.REQUESTER_DENIED
        
        # 建立會話
        syn = pending["syn"]
        syn_ack = pending["syn_ack"]
        
        session = SIT_Session(
            session_id=session_id,
            session_token=ack.session_token,
            requester_id=syn.requester_id,
            responder_id=self.entity_id,
            agreed_scope=syn_ack.accepted_scope,
            agreed_constraints={
                **syn_ack.constraints_accepted,
                **syn_ack.constraints_modified
            },
            semantic_mode=ack.semantic_mode,
            state=SIT_HandshakeState.ESTABLISHED,
            established_at=datetime.utcnow().isoformat() + "Z",
            expires_at=(datetime.utcnow() + timedelta(hours=1)).isoformat() + "Z",
            signature_chain=[
                syn.signature,
                syn_ack.signature,
                ack.signature
            ]
        )
        
        self.established_sessions[session_id] = session
        self.pending_sessions.pop(session_id, None)
        
        return session, None
    
    # ========== 工具方法 ==========
    
    def _sign(self, data: Dict) -> str:
        """計算 HMAC 簽名"""
        # 移除簽名欄位
        data_copy = {k: v for k, v in data.items() if k != 'signature'}
        # 使用 JSON 序列化以確保一致的格式
        payload = json.dumps(data_copy, sort_keys=True, ensure_ascii=False).encode('utf-8')
        return hmac.new(self.secret_key, payload, hashlib.sha256).hexdigest()
    
    def _verify_signature(self, data: Dict, signature: str) -> bool:
        """驗證簽名"""
        expected = self._sign(data)
        return hmac.compare_digest(expected, signature or "")
    
    def _is_timeout(self, start_time: datetime, ttl_seconds: int) -> bool:
        """檢查是否超時"""
        if isinstance(start_time, str):
            start_time = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        elapsed = (datetime.utcnow() - start_time.replace(tzinfo=None)).total_seconds()
        return elapsed > ttl_seconds
    
    def get_session(self, session_id: str) -> Optional[SIT_Session]:
        """取得已建立的會話"""
        return self.established_sessions.get(session_id)
    
    def is_session_valid(self, session_id: str) -> bool:
        """檢查會話是否有效"""
        session = self.established_sessions.get(session_id)
        if not session:
            return False
        
        try:
            expires = datetime.fromisoformat(session.expires_at.replace('Z', '+00:00'))
            return datetime.utcnow() < expires.replace(tzinfo=None)
        except:
            return False


# ========== 測試 ==========

if __name__ == "__main__":
    print("=== SIT 三次握手測試 ===\n")
    
    # 模擬兩個實體
    alice = SIT_Handshake(secret_key="alice-secret", entity_id="alice-001")
    bob = SIT_Handshake(secret_key="bob-secret", entity_id="bob-001")
    
    # Step 1: Alice 發送 SYN
    print("--- Step 1: Alice → SYN → Bob ---")
    syn = alice.create_syn(
        intent_scope="查詢用戶資料",
        semantic_boundary={
            "data_types": ["profile", "transaction"],
            "time_range": "last_30_days"
        },
        constraints={
            "max_tokens": 1000,
            "allowed_operations": ["READ"]
        }
    )
    print(f"Session ID: {syn.session_id}")
    print(f"Intent: {syn.intent_scope}")
    print(f"Signature: {syn.signature[:32]}...")
    
    # Step 2: Bob 處理 SYN，回覆 SYN-ACK
    print("\n--- Step 2: Bob → SYN-ACK → Alice ---")
    syn_ack, error = bob.process_syn(
        syn,
        accept=True,
        modified_constraints={"max_tokens": 500}  # Bob 限制 token 數
    )
    if error:
        print(f"錯誤: {error}")
    else:
        print(f"Accepted Scope: {syn_ack.accepted_scope}")
        print(f"Session Token: {syn_ack.session_token}")
        print(f"Modified: max_tokens → 500")
        print(f"Signature: {syn_ack.signature[:32]}...")
    
    # Step 3: Alice 處理 SYN-ACK，回覆 ACK
    print("\n--- Step 3: Alice → ACK → Bob ---")
    ack, error = alice.process_syn_ack(syn_ack)
    if error:
        print(f"錯誤: {error}")
    else:
        print(f"Confirmed: {ack.confirmed}")
        print(f"Semantic Mode: {ack.semantic_mode}")
        print(f"Signature: {ack.signature[:32]}...")
    
    # Step 4: Bob 處理 ACK，建立會話
    print("\n--- Step 4: Session Established ---")
    session, error = bob.process_ack(ack)
    if error:
        print(f"錯誤: {error}")
    else:
        print(f"Session ID: {session.session_id}")
        print(f"State: {session.state}")
        print(f"Agreed Scope: {session.agreed_scope}")
        print(f"Agreed Constraints: {session.agreed_constraints}")
        print(f"Expires: {session.expires_at}")
    
    # 驗證雙方會話
    print("\n--- 會話驗證 ---")
    print(f"Alice 會話有效: {alice.is_session_valid(syn.session_id)}")
    print(f"Bob 會話有效: {bob.is_session_valid(syn.session_id)}")
    
    print("\n✅ SIT 三次握手測試完成")
