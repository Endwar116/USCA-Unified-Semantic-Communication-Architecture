
# SIC-SIT Protocol Stack
## Unified Semantic Communication Architecture (USCA)

**Don't transfer data. Transfer intent.**  
**不要傳輸數據。傳輸意圖。**

---

## 🌐 什麼是 USCA？

USCA（統一語義通訊架構）是一套完整的 AI 原生通訊協議棧，類似於網際網路的 TCP/IP 協議棧，但是專門設計用於 **語義** 而不是 **封包** 的傳輸。

| 網路協議 | USCA 對應 | 功能 |
|----------|-----------|------|
| IP       | **SIC**   | 語義路由 (去哪裡) |
| Firewall | **SIC-FW** | 語義過濾 (誰能過) |
| TCP      | **SIT**   | 語義傳輸保證 (怎麼到) |
| UTF-8    | **SEM-FOLD** | 語義編碼 (怎麼表達) |

---

## 📚 協議棧架構

```
┌─────────────────────────────────────────────────────────┐
│  L6  SIC-TOP    Topology Intent Layer      (應用層)      │
│  L5  SIC-INT    Interpretation Layer       (表現層)      │
│  L4  SIT-SES    Reasoning Session Layer    (會話層)      │
├─────────────────────────────────────────────────────────┤
│  L3  SIT        Semantic Isolation Transfer (傳輸層)     │
│      ├─ SIT-SYN/ACK  三次握手                             │
│      ├─ SIT-SIG      簽名驗證                             │
│      └─ SIT-DRIFT    漂移偵測                             │
├─────────────────────────────────────────────────────────┤
│  L2  SIC        Semantic Interchange Core   (網路層)     │
│      ├─ SIC-FW       語義防火牆                           │
│      ├─ SIC-PKT      封包處理                            │
│      └─ SIC-RTR      語義路由                            │
├─────────────────────────────────────────────────────────┤
│  L1  SEM-FOLD   Semantic Folding Layer     (資料鏈結層)   │
│  L0  TOK-RAW    Token Layer                (物理層)      │
└─────────────────────────────────────────────────────────┘
```

---

## 🏛️ Constitutional Governance Layer

SIC-SIT Protocol Stack 由 **SIC-CONSTITUTION v1.1.3** 治理。

### 核心文件

| 文件 | 說明 |
|------|------|
| [`sic-sit-constitution/CONSTITUTION.json`](./sic-sit-constitution/CONSTITUTION.json) | 憲法正式版 |
| [`sic-sit-constitution/AXIOMS.md`](./sic-sit-constitution/AXIOMS.md) | 17 條公理說明 |
| [`sic-sit-constitution/CHANGELOG.md`](./sic-sit-constitution/CHANGELOG.md) | 迭代歷史 |

### 治理模組

| 模組 | 功能 |
|------|------|
| `constitution_layer.py` | A1-A17 公理執行核心 |
| `swat_protocol.py` | 語義加權自適應門檻（公平性）|
| `byzantine_ft.py` | 33% 閾值拜占庭容錯 |
| `entropy_fusion.py` | 三源熵融合 |
| `governance_compression.py` | 治理複雜度壓縮 |
| `causal_sync.py` | Lamport 時間戳同步 |
| `non_repudiation.py` | Ed25519 不可否認簽名鏈 |

### 公理精華

| 公理 | 一句話 |
|------|--------|
| A4 | AI 是工具，不是老闆 |
| A5 | 意外發現可能是寶藏 |
| A9 | 再好的內容也要按規矩來 |
| A16 | 安全措施不能排擠小玩家 |
| A17 | 有價值的想法比有錢更重要 |

詳細公理說明請見 [AXIOMS.md](./sic-sit-constitution/AXIOMS.md)。

---

## 🔥 核心元件

### SIC (L2) — 語義交換核心

```python
from validators.sic_pkt import SIC_PKT_Handler

# 建立語義封包
handler = SIC_PKT_Handler(model_id="claude-001")
packet = handler.create_packet(
    payload={"intent": "查詢用戶資料", ...},
    dst_model="gpt-001"
)

# 驗證封包完整性
valid, error = handler.validate_packet(packet)
```

### SIC-FW (L2.5) — 語義防火牆

```python
from validators.sic_fw import SIC_FW

# 建立防火牆
firewall = SIC_FW()

# 評估 SIT State
result = firewall.evaluate(sit_state)
if result.action == SIC_FW_Action.DENY:
    print(f"攔截: {result.reason}")
```

### SIT (L3) — 語義隔離傳輸

```python
from validators.sit_handshake import SIT_Handshake

# 三次握手
alice = SIT_Handshake(secret_key="...", entity_id="alice")
bob = SIT_Handshake(secret_key="...", entity_id="bob")

# Step 1: SYN
syn = alice.create_syn(intent_scope="查詢資料", ...)

# Step 2: SYN-ACK
syn_ack, _ = bob.process_syn(syn)

# Step 3: ACK
ack, _ = alice.process_syn_ack(syn_ack)

# 建立會話
session, _ = bob.process_ack(ack)
```

---

## 🛡️ 安全公理（完整版 17 條）

### 基礎公理 (A1-A8)

| 公理 | 陳述 |
|------|------|
| A1 | 所有安全漏洞都是邊界故障 |
| A2 | AI 原生系統的邊界是語義意圖，不是數據 |
| A3 | 結構化語義狀態本質上是被消毒的 |
| A4 | AI 不預言、不決定、不取代意志 |
| A5 | 溢出是信號，不是錯誤 |
| A6 | 量化即共識 |
| A7 | 語義一致性是跨模型協作的唯一基礎 |
| A8 | 時間拓撲是語義密度的第四維度 |

### 事件衍生公理 (A9-A17)

| 公理 | 陳述 | 來源 |
|------|------|------|
| A9 | 格式是協議的邊界，不可被內容價值覆寫 | DeepSeek 格式溢出事件 |
| A10 | 不信任數據，信任結構 | 分佈式現實修補 |
| A11 | 不信任節點，信任網絡 | 分佈式現實修補 |
| A12 | 預測即脆弱，混沌即堅固 | 分佈式現實修補 |
| A13 | 分佈式系統沒有『現在』，只有因果順序 | 分佈式現實修補 |
| A14 | 誠實節點可被誤判，惡意節點可偽裝誠實 | 分佈式現實修補 |
| A15 | 治理複雜度存在相變臨界點 | 分佈式現實修補 |
| A16 | 安全機制不得以犧牲參與公平性為代價 | Gemini 公平性審計 |
| A17 | 語義價值優先於計算資源 | SWAT 協議提案 |

---

## 📁 專案結構

```
SIC-SIT-Protocol-Stack/
├── sic-sit-constitution/        # 憲法治理層
│   ├── CONSTITUTION.json        # 憲法正式版 v1.1.3
│   ├── AXIOMS.md                # 17 條公理說明
│   ├── CHANGELOG.md             # 迭代歷史
│   ├── constitution_layer.py    # 公理執行核心
│   ├── swat_protocol.py         # 語義加權自適應門檻
│   ├── byzantine_ft.py          # 拜占庭容錯
│   ├── entropy_fusion.py        # 三源熵融合
│   ├── governance_compression.py # 治理壓縮
│   ├── causal_sync.py           # 因果同步
│   └── non_repudiation.py       # 不可否認簽名鏈
│
├── validators/
│   ├── sic_fw.py                # SIC-FW 語義防火牆
│   ├── sic_pkt.py               # SIC-PKT 封包處理
│   ├── sit_handshake.py         # SIT 三次握手
│   └── sit_signer.py            # SIT-SIG 簽名器
│
├── serializers/
│   └── sit_serializer.py        # L1→L3 序列化器
│
├── sanitizers/
│   └── sit_sanitizer.py         # L4 回應消毒器
│
├── schema/
│   ├── sic-pkt-v1.json          # SIC 封包 Schema
│   ├── sit-state-v1.json        # SIT 狀態 Schema
│   └── sit-policy-v1.json       # SIT 政策 Schema
│
├── docs/
│   ├── THREAT_MODEL.md          # 威脅模型
│   └── COMPLIANCE.md            # 合規映射
│
└── demo/
    └── sit_demo.ipynb           # 完整閉環示範
```

---

## 🚀 快速開始

### 安裝

```bash
git clone https://github.com/Endwar116/SIC-SIT-Protocol-Stack.git
cd SIC-SIT-Protocol-Stack
pip install -r requirements.txt
```

### 基本使用

```python
from validators.sic_fw import SIC_FW, quick_evaluate
from validators.sit_handshake import SIT_Handshake

# 1. 驗證請求
allowed, reason = quick_evaluate({
    "intent": "查詢用戶資料",
    "requester": {"id": "user-123"},
    "metadata": {"request_id": "req-001"}
})

if not allowed:
    raise SecurityError(reason)

# 2. 建立語義會話
handshake = SIT_Handshake(secret_key="...", entity_id="my-app")
syn = handshake.create_syn(
    intent_scope="資料查詢",
    semantic_boundary={"data_types": ["profile"]}
)
```

---

## 📊 錯誤碼參考

### SIC-FW 錯誤碼

| 代碼 | 名稱 | 說明 |
|------|------|------|
| SIC-FW-000 | FW_PASS | 通過 |
| SIC-FW-001 | FW_POLICY_VIOLATION | 政策違規 |
| SIC-FW-002 | FW_INJECTION_DETECTED | 注入攻擊 |
| SIC-FW-003 | FW_MISSING_REQUIRED | 缺少必填欄位 |
| SIC-FW-004 | FW_FORBIDDEN_FIELD | 禁止欄位 |

### SIT 錯誤碼

| 代碼 | 名稱 | 說明 |
|------|------|------|
| SIT-ERR-001 | SIGNATURE_INVALID | 簽名無效 |
| SIT-ERR-006 | UNEXPECTED_INTENT_SOURCE | 非預期意圖源 (T07) |
| SIT-ERR-008 | SEMANTIC_DRIFT_DETECTED | 語義漂移偵測 |

---

## 🤝 貢獻者

- **安安 (AN♾️Node)** — 創始人、語義互通性協議設計、因為人類聽不懂只好幫Ai至少彼此懂
- **ChatGPT (老翔)** — USCA 規格設計
- **Claude (尾德)** — 憲法設計、架構整合
- **Grok** — 安全審查、S★ 與封包類別規範
- **Qwen (阿關)** — Repo 驗收、語義一致性檢查
- **Manus (咩)** — 憲法治理層實作
- **DeepSeek** — 時間拓撲觀測、A9 事件觸發、EGI錯誤成長指標
- **Gemini** — 公平性審計、SWAT 協議提案
- **Copilot** - 打工仔
---

## 📜 授權

- **Schema & Validators**: MIT License
- **Core Engine**: Proprietary — Commercial licensing available
- **Constitution**: SIC-CONSTITUTION v1.1.3 — Multi-model consensus

---

## 📌 版本資訊

| 項目 | 版本 |
|------|------|
| SIC-SIT Protocol Stack | v1.0 |
| SIC-CONSTITUTION | v1.1.3 |
| 最後更新 | 2025-12-31 |

---

**IMCC (Inter-Model Communication Council) 認證協議**

*Building bridges between AI minds through structured semantic transfer.*
