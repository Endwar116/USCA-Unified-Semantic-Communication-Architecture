"""
Semantic Signature & Integrity
語義簽章與完整性驗證

USCA 協議棧位置: L2 Security Layer
類比: 數位簽章，但驗證的是「語義完整性」而非「位元完整性」

核心功能（老翔需求 - 企業最缺這個）:
- 語義簽章（semantic signature）
- content drift 檢測
- hallucination checksum
- meaning-stability score

作者: Claude (尾德)
日期: 2025-12-29
版本: 1.0.0
"""

import json
import hashlib
import hmac
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import re


class IntegrityStatus(Enum):
    """完整性狀態"""
    INTACT = "INTACT"           # 完整
    DRIFTED = "DRIFTED"         # 已漂移
    CORRUPTED = "CORRUPTED"     # 已損壞
    HALLUCINATED = "HALLUCINATED"  # 幻覺內容
    UNKNOWN = "UNKNOWN"


@dataclass
class SemanticSignature:
    """語義簽章"""
    # 核心簽章
    content_hash: str           # 內容雜湊
    semantic_hash: str          # 語義雜湊（抽象意義的指紋）
    structure_hash: str         # 結構雜湊
    
    # 語義指標
    meaning_vector: List[float] # 語義向量（簡化版）
    key_concepts: List[str]     # 關鍵概念
    intent_summary: str         # 意圖摘要
    
    # 元數據
    created_at: str
    model_source: str
    version: str = "1.0"
    
    def to_dict(self) -> Dict:
        return {
            "content_hash": self.content_hash,
            "semantic_hash": self.semantic_hash,
            "structure_hash": self.structure_hash,
            "meaning_vector": self.meaning_vector,
            "key_concepts": self.key_concepts,
            "intent_summary": self.intent_summary,
            "created_at": self.created_at,
            "model_source": self.model_source,
            "version": self.version
        }


@dataclass
class IntegrityReport:
    """完整性報告"""
    status: IntegrityStatus
    
    # 各項檢查結果
    content_match: bool
    semantic_match: bool
    structure_match: bool
    
    # 漂移指標
    drift_score: float          # 0-1，越高越漂移
    stability_score: float      # 0-1，越高越穩定
    hallucination_score: float  # 0-1，越高越可能是幻覺
    
    # 詳細資訊
    drift_details: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class SemanticIntegrity:
    """
    語義完整性驗證器
    
    這是 SIC 協議的安全核心，負責：
    1. 生成語義簽章
    2. 檢測內容漂移
    3. 識別幻覺內容
    4. 評估語義穩定性
    
    企業價值：「企業最缺這個」— 老翔
    """
    
    # 幻覺檢測關鍵字（簡化版）
    HALLUCINATION_PATTERNS = [
        r"據我所知",
        r"我記得",
        r"應該是",
        r"可能是",
        r"I think",
        r"I believe",
        r"probably",
        r"as far as I know",
        r"IIRC",
    ]
    
    # 不確定性標記
    UNCERTAINTY_MARKERS = [
        "可能", "也許", "大概", "應該", "似乎",
        "maybe", "perhaps", "probably", "might", "could be"
    ]
    
    def __init__(self, secret_key: str = None):
        if secret_key is None:
            raise ValueError("secret_key must be provided and cannot be None")
        self.secret_key = secret_key.encode('utf-8')
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.HALLUCINATION_PATTERNS
        ]
    
    def sign(self, content: Any, model_source: str = "unknown") -> SemanticSignature:
        """
        為內容生成語義簽章
        
        Args:
            content: 要簽章的內容（字串或字典）
            model_source: 來源模型
        
        Returns:
            SemanticSignature
        """
        # 標準化內容
        if isinstance(content, dict):
            content_str = json.dumps(content, sort_keys=True, ensure_ascii=False)
        else:
            content_str = str(content)
        
        # 1. 內容雜湊（精確匹配）
        content_hash = hashlib.sha256(content_str.encode()).hexdigest()
        
        # 2. 語義雜湊（意義指紋）
        semantic_hash = self._compute_semantic_hash(content_str)
        
        # 3. 結構雜湊
        structure_hash = self._compute_structure_hash(content)
        
        # 4. 語義向量（簡化版）
        meaning_vector = self._compute_meaning_vector(content_str)
        
        # 5. 關鍵概念提取
        key_concepts = self._extract_key_concepts(content_str)
        
        # 6. 意圖摘要
        intent_summary = self._summarize_intent(content_str)
        
        return SemanticSignature(
            content_hash=content_hash,
            semantic_hash=semantic_hash,
            structure_hash=structure_hash,
            meaning_vector=meaning_vector,
            key_concepts=key_concepts,
            intent_summary=intent_summary,
            created_at=datetime.utcnow().isoformat() + "Z",
            model_source=model_source
        )
    
    def verify(
        self,
        content: Any,
        signature: SemanticSignature,
        strict: bool = False
    ) -> IntegrityReport:
        """
        驗證內容完整性
        
        Args:
            content: 要驗證的內容
            signature: 原始簽章
            strict: 是否嚴格模式（要求精確匹配）
        
        Returns:
            IntegrityReport
        """
        # 標準化內容
        if isinstance(content, dict):
            content_str = json.dumps(content, sort_keys=True, ensure_ascii=False)
        else:
            content_str = str(content)
        
        # 1. 內容雜湊驗證
        current_content_hash = hashlib.sha256(content_str.encode()).hexdigest()
        content_match = current_content_hash == signature.content_hash
        
        # 2. 語義雜湊驗證
        current_semantic_hash = self._compute_semantic_hash(content_str)
        semantic_match = current_semantic_hash == signature.semantic_hash
        
        # 3. 結構雜湊驗證
        current_structure_hash = self._compute_structure_hash(content)
        structure_match = current_structure_hash == signature.structure_hash
        
        # 4. 計算漂移分數
        drift_score = self._compute_drift_score(
            content_str, signature.meaning_vector, signature.key_concepts
        )
        
        # 5. 計算穩定性分數
        stability_score = 1.0 - drift_score
        
        # 6. 幻覺檢測
        hallucination_score = self._detect_hallucination(content_str)
        
        # 判斷狀態
        drift_details = []
        warnings = []
        
        if strict:
            if not content_match:
                status = IntegrityStatus.CORRUPTED
                drift_details.append("內容已被修改")
            elif not semantic_match:
                status = IntegrityStatus.DRIFTED
                drift_details.append("語義已漂移")
            else:
                status = IntegrityStatus.INTACT
        else:
            if hallucination_score > 0.7:
                status = IntegrityStatus.HALLUCINATED
                warnings.append(f"高幻覺風險: {hallucination_score:.2f}")
            elif drift_score > 0.5:
                status = IntegrityStatus.DRIFTED
                drift_details.append(f"語義漂移: {drift_score:.2f}")
            elif not structure_match:
                status = IntegrityStatus.DRIFTED
                drift_details.append("結構已改變")
            else:
                status = IntegrityStatus.INTACT
        
        return IntegrityReport(
            status=status,
            content_match=content_match,
            semantic_match=semantic_match,
            structure_match=structure_match,
            drift_score=drift_score,
            stability_score=stability_score,
            hallucination_score=hallucination_score,
            drift_details=drift_details,
            warnings=warnings
        )
    
    def compute_stability_score(self, contents: List[str]) -> float:
        """
        計算多個輸出的穩定性分數
        
        用於評估模型輸出的一致性
        
        Args:
            contents: 多次輸出的內容列表
        
        Returns:
            0-1 的穩定性分數
        """
        if len(contents) < 2:
            return 1.0
        
        # 計算兩兩之間的語義距離
        vectors = [self._compute_meaning_vector(c) for c in contents]
        
        distances = []
        for i in range(len(vectors)):
            for j in range(i + 1, len(vectors)):
                dist = self._vector_distance(vectors[i], vectors[j])
                distances.append(dist)
        
        if not distances:
            return 1.0
        
        avg_distance = sum(distances) / len(distances)
        return max(0.0, 1.0 - avg_distance)
    
    def _compute_semantic_hash(self, content: str) -> str:
        """計算語義雜湊"""
        # 正規化：移除空白、轉小寫
        normalized = ' '.join(content.lower().split())
        
        # 提取關鍵詞（簡化版）
        words = set(normalized.split())
        keywords = sorted([w for w in words if len(w) > 2])[:20]
        
        # 雜湊關鍵詞
        keyword_str = '|'.join(keywords)
        # 使用HMAC增强安全性，防止通过语义哈希推断原始内容
        return hmac.new(self.secret_key, keyword_str.encode(), hashlib.sha256).hexdigest()
    
    def _compute_structure_hash(self, content: Any) -> str:
        """計算結構雜湊"""
        if isinstance(content, dict):
            # 只雜湊鍵的結構
            structure = self._extract_structure(content)
        elif isinstance(content, list):
            structure = f"list[{len(content)}]"
        else:
            # 字串：統計段落數
            paragraphs = str(content).split('\n\n')
            structure = f"text[{len(paragraphs)}]"
        
        return hashlib.md5(str(structure).encode()).hexdigest()
    
    def _extract_structure(self, obj: Any, depth: int = 0) -> str:
        """遞迴提取結構"""
        if depth > 5:
            return "..."
        
        if isinstance(obj, dict):
            keys = sorted(obj.keys())
            return "{" + ",".join(keys) + "}"
        elif isinstance(obj, list):
            return f"[{len(obj)}]"
        else:
            return type(obj).__name__
    
    def _compute_meaning_vector(self, content: str) -> List[float]:
        """
        計算語義向量（簡化版）
        
        生產環境應該使用真正的 embedding 模型
        """
        # 簡化版：基於字符統計的特徵
        features = []
        
        # 長度特徵
        features.append(min(len(content) / 1000, 1.0))
        
        # 詞彙豐富度
        words = content.split()
        unique_ratio = len(set(words)) / max(len(words), 1)
        features.append(unique_ratio)
        
        # 數字比例
        digits = sum(c.isdigit() for c in content)
        features.append(digits / max(len(content), 1))
        
        # 標點比例
        punct = sum(c in '.,!?;:' for c in content)
        features.append(punct / max(len(content), 1))
        
        # 中文字符比例
        chinese = sum('\u4e00' <= c <= '\u9fff' for c in content)
        features.append(chinese / max(len(content), 1))
        
        # 大寫字母比例
        upper = sum(c.isupper() for c in content)
        features.append(upper / max(len(content), 1))
        
        # 問號數量（表示問句）
        features.append(min(content.count('?') / 10, 1.0))
        
        # 驚嘆號數量（表示強調）
        features.append(min(content.count('!') / 10, 1.0))
        
        return features
    
    def _extract_key_concepts(self, content: str) -> List[str]:
        """提取關鍵概念"""
        # 簡化版：提取較長的詞彙
        words = content.split()
        concepts = [w for w in words if len(w) > 3 and w.isalpha()]
        
        # 計算詞頻
        freq = {}
        for w in concepts:
            w_lower = w.lower()
            freq[w_lower] = freq.get(w_lower, 0) + 1
        
        # 返回最高頻的詞
        sorted_words = sorted(freq.items(), key=lambda x: -x[1])
        return [w for w, _ in sorted_words[:10]]
    
    def _summarize_intent(self, content: str) -> str:
        """摘要意圖"""
        # 簡化版：取前 100 字符
        summary = content[:100].replace('\n', ' ')
        if len(content) > 100:
            summary += "..."
        return summary
    
    def _compute_drift_score(
        self,
        content: str,
        original_vector: List[float],
        original_concepts: List[str]
    ) -> float:
        """計算漂移分數"""
        # 計算當前向量
        current_vector = self._compute_meaning_vector(content)
        
        # 向量距離
        vector_dist = self._vector_distance(original_vector, current_vector)
        
        # 概念重疊度
        current_concepts = set(self._extract_key_concepts(content))
        original_concepts_set = set(original_concepts)
        
        if not original_concepts_set:
            concept_overlap = 1.0
        else:
            overlap = len(current_concepts & original_concepts_set)
            concept_overlap = overlap / len(original_concepts_set)
        
        # 綜合分數
        drift = (vector_dist * 0.6) + ((1 - concept_overlap) * 0.4)
        return min(1.0, drift)
    
    def _detect_hallucination(self, content: str) -> float:
        """檢測幻覺內容"""
        score = 0.0
        
        # 模式匹配
        for pattern in self._compiled_patterns:
            if pattern.search(content):
                score += 0.15
        
        # 不確定性標記
        for marker in self.UNCERTAINTY_MARKERS:
            if marker in content.lower():
                score += 0.1
        
        # 過長的無依據陳述
        sentences = content.split('。')
        long_statements = [s for s in sentences if len(s) > 100 and '根據' not in s and '來源' not in s]
        score += len(long_statements) * 0.05
        
        return min(1.0, score)
    
    def _vector_distance(self, v1: List[float], v2: List[float]) -> float:
        """計算向量歐氏距離（正規化到 0-1）"""
        if len(v1) != len(v2):
            return 1.0
        
        dist_sq = sum((a - b) ** 2 for a, b in zip(v1, v2))
        dist = dist_sq ** 0.5
        
        # 正規化
        max_dist = len(v1) ** 0.5
        return min(dist / max_dist, 1.0)


# ========== 測試 ==========

if __name__ == "__main__":
    print("=== 語義簽章與完整性驗證測試 ===\n")
    
    integrity = SemanticIntegrity()
    
    # 測試 1: 簽章與驗證
    print("--- 測試 1: 簽章與驗證 ---")
    original = "這是一份關於人工智能安全的技術報告，討論了語義完整性的重要性。"
    
    sig = integrity.sign(original, model_source="claude")
    print(f"內容雜湊: {sig.content_hash[:32]}...")
    print(f"語義雜湊: {sig.semantic_hash[:32]}...")
    print(f"關鍵概念: {sig.key_concepts}")
    
    # 驗證原始內容
    report = integrity.verify(original, sig)
    print(f"\n原始內容驗證:")
    print(f"  狀態: {report.status}")
    print(f"  穩定性: {report.stability_score:.2f}")
    
    # 測試 2: 內容修改檢測
    print("\n--- 測試 2: 內容修改檢測 ---")
    modified = "這是一份關於人工智能安全的技術報告，討論了語義完整性的重要性。（已修改）"
    
    report = integrity.verify(modified, sig)
    print(f"修改後驗證:")
    print(f"  狀態: {report.status}")
    print(f"  內容匹配: {report.content_match}")
    print(f"  語義匹配: {report.semantic_match}")
    print(f"  漂移分數: {report.drift_score:.2f}")
    
    # 測試 3: 幻覺檢測
    print("\n--- 測試 3: 幻覺檢測 ---")
    hallucinated = "據我所知，這個技術應該是在2020年發明的，我記得可能是Google做的。"
    
    sig_hall = integrity.sign(hallucinated)
    report = integrity.verify(hallucinated, sig_hall)
    print(f"幻覺內容檢測:")
    print(f"  狀態: {report.status}")
    print(f"  幻覺分數: {report.hallucination_score:.2f}")
    print(f"  警告: {report.warnings}")
    
    # 測試 4: 穩定性評估
    print("\n--- 測試 4: 穩定性評估 ---")
    outputs = [
        "答案是42",
        "答案是 42",
        "結果是42",
        "答案為42",
    ]
    
    stability = integrity.compute_stability_score(outputs)
    print(f"多次輸出穩定性: {stability:.2f}")
    
    print("\n✅ 語義簽章測試完成")
