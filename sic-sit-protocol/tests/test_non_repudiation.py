"""
SIC-SIT 憲法治理層測試腳本
驗證公理驗證、SWAT、拜占庭容錯、熵融合等功能
"""

import json
from database_schema import SICSTDatabase
from constitution_layer import ConstitutionLayer
from swat_protocol import SWATProtocol
from byzantine_ft import ByzantineFaultTolerance
from entropy_fusion import EntropyFusion
from governance_compression import GovernanceCompression
from causal_sync import CausalEntropySync
from non_repudiation import NonRepudiationChain

def print_section(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")

def test_constitution_axioms():
    print_section("測試 1: 憲法公理驗證 (Constitution Layer)")
    db = SICSTDatabase("test_constitution.db")
    cl = ConstitutionLayer(db)
    
    # 測試正常操作
    context_ok = {
        "boundary_defined": True,
        "is_semantic_intent": True,
        "is_structured": True,
        "replaces_human_will": False,
        "is_quantifiable": True,
        "semantic_consistent": True,
        "has_temporal_marker": True,
        "format_compliant": True,
        "structure_verified": True,
        "network_consensus": True,
        "entropy_sufficient": True,
        "has_causal_order": True,
        "signature_verified": True,
        "complexity_score": 2.0,
        "fairness_score": 0.8
    }
    
    result_ok = cl.validate_operation("TEST_OP", context_ok)
    print(f"✅ 正常操作驗證: {'通過' if result_ok['valid'] else '失敗'}")
    
    # 測試違反 A4 (最高優先級)
    context_violate_a4 = context_ok.copy()
    context_violate_a4["replaces_human_will"] = True
    
    result_a4 = cl.validate_operation("DANGEROUS_OP", context_violate_a4)
    print(f"⚠️  違反 A4 驗證: {'攔截成功' if not result_a4['valid'] else '攔截失敗'}")
    print(f"   訊息: {result_a4.get('message')}")
    
    # 測試多重違規
    context_multi = context_ok.copy()
    context_multi["boundary_defined"] = False
    context_multi["is_structured"] = False
    
    result_multi = cl.validate_operation("MULTI_VIOLATION", context_multi)
    print(f"📝 多重違規偵測: 發現 {len(result_multi['violations'])} 個違規")
    for v in result_multi['violations']:
        print(f"   - {v['axiom']}: {v['statement']}")
    
    db.close()

def test_swat_protocol():
    print_section("測試 2: SWAT 協議 (語義加權自適應門檻)")
    db = SICSTDatabase("test_swat.db")
    swat = SWATProtocol(db)
    
    # 測試新穎性分數
    v1 = [1.0, 0.0, 0.0]
    existing = [[0.9, 0.1, 0.0], [0.1, 0.9, 0.0]]
    novelty = swat.calculate_novelty_score(v1, existing)
    print(f"✨ 新穎性分數: {novelty:.4f}")
    
    # 測試難度計算
    diff_low = swat.calculate_effective_difficulty(0.1, 0.9, 80, "tier_1_edge")
    diff_high = swat.calculate_effective_difficulty(0.8, 0.1, 10, "tier_3_heavy")
    
    print(f"📉 低負載/高新穎性/高信譽難度: {diff_low:.4f}")
    print(f"📈 高負載/低新穎性/低信譽難度: {diff_high:.4f}")
    
    # 測試公平性
    node_stats = {"node1": 100, "node2": 10, "node3": 5}
    fairness = swat.check_fairness(node_stats)
    print(f"⚖️  公平性檢查: {'違反' if fairness['fairness_violated'] else '正常'}")
    print(f"   最大佔比: {fairness['max_single_share']:.2%}")
    
    db.close()

def test_byzantine_ft():
    print_section("測試 3: 拜占庭容錯 (BFT)")
    db = SICSTDatabase("test_bft.db")
    bft = ByzantineFaultTolerance(db)
    
    # 模擬節點行為
    nodes = ["node_A", "node_B", "node_C", "node_D"]
    for node in nodes:
        bft.update_node_trust(node, True)
    
    # 讓一個節點變壞
    bft.update_node_trust("node_D", False)
    bft.update_node_trust("node_D", False)
    
    status = bft.check_byzantine_ratio()
    print(f"🛡️  拜占庭狀態: {'安全' if status['safe'] else '危險'}")
    print(f"   比例: {status['ratio']:.2%}")
    
    # 讓更多節點變壞
    bft.update_node_trust("node_C", False)
    bft.update_node_trust("node_C", False)
    
    status_bad = bft.check_byzantine_ratio()
    print(f"🚨 拜占庭狀態 (多節點失效): {'安全' if status_bad['safe'] else '危險'}")
    print(f"   比例: {status_bad['ratio']:.2%}")
    print(f"   觸發動作: {status_bad['action_required']}")
    
    db.close()

def test_entropy_and_sync():
    print_section("測試 4: 熵融合與因果同步")
    db = SICSTDatabase("test_entropy.db")
    ef = EntropyFusion(db)
    cs = CausalEntropySync()
    
    # 熵融合
    h1 = ef.fuse_entropy("semantic_1")
    h2 = ef.fuse_entropy("semantic_2")
    print(f"🎲 融合哈希 1: {h1[:16]}...")
    print(f"🎲 融合哈希 2: {h2[:16]}...")
    
    indep = ef.check_independence()
    print(f"🔍 獨立性檢查: {indep['message']} (分數: {indep['independence_score']:.4f})")
    
    # 因果同步
    e1 = cs.send_event("node_1")
    e2 = cs.send_event("node_2")
    
    print(f"⏰ 事件 1 時間戳: {e1['lamport_timestamp']}")
    print(f"⏰ 事件 2 時間戳: {e2['lamport_timestamp']}")
    print(f"🔗 因果順序 (E1 < E2): {cs.happens_before(e1, e2)}")
    
    db.close()

def test_non_repudiation():
    print_section("測試 5: 不可否認簽名鏈")
    db = SICSTDatabase("test_nr.db")
    nr = NonRepudiationChain(db)
    
    stc = {"id": "stc_123", "content": "hello world"}
    
    # 簽名
    sig_data = nr.sign_stc("node_A", stc)
    print(f"🔏 簽名完成: {sig_data['signature'][:16]}...")
    
    # 驗證
    is_valid = nr.verify_signature(stc, sig_data)
    print(f"✅ 簽名驗證: {'成功' if is_valid else '失敗'}")
    
    # 證明鏈
    chain = nr.create_proof_chain(stc, ["node_A", "node_B"])
    print(f"⛓️  證明鏈長度: {chain['chain_length']}")
    
    db.close()

if __name__ == "__main__":
    test_constitution_axioms()
    test_swat_protocol()
    test_byzantine_ft()
    test_entropy_and_sync()
    test_non_repudiation()
    print_section("✅ 所有憲法治理層測試完成")
