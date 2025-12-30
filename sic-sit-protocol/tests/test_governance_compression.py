from database_schema import SICSTDatabase
from governance_compression import GovernanceCompression

def test_governance_compression():
    db = SICSTDatabase("test_comp.db")
    gc = GovernanceCompression(db)
    
    # 1. 正常複雜度
    comp_low = gc.calculate_complexity(5, 0.1, 0.1)
    print(f"📊 低複雜度分數: {comp_low:.4f}")
    
    # 2. 高複雜度
    comp_high = gc.calculate_complexity(25, 0.4, 0.5)
    print(f"📊 高複雜度分數: {comp_high:.4f}")
    
    # 3. 壓縮判定
    should_comp = gc.should_compress(25, comp_high)
    print(f"📦 壓縮判定: {'需要壓縮' if should_comp else '無需壓縮'}")
    
    # 4. 生成摘要
    state = {
        "node_count": 25,
        "complexity_score": comp_high,
        "byzantine_ratio": 0.4,
        "alerts": ["HIGH_COMPLEXITY"]
    }
    summary = gc.generate_compressed_summary(state)
    print(f"📝 摘要生成: {'成功' if summary['compressed'] else '失敗'}")
    print(f"   階段: {summary['key_metrics']['phase']}")
    
    db.close()

if __name__ == "__main__":
    test_governance_compression()
