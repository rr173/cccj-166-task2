# 工业控制指令双通道确认网关

高风险工业控制指令（紧急停车、切电、旁路开启等）的**创建**与**确认下发**强制分离在
两条互相独立的通道上，并由网关向现场设备做一次确认性投递；设备回执携带
**启动代号（boot_code）+ 严格递增序号（seq）**，所有状态变迁写入
**append-only 哈希链审计日志**。

> 纯 Python 3 标准库实现，无任何第三方依赖。60 个测试（42 单元 + 18 端到端）全部通过。

## 一、安全模型（如何对应需求）

| 需求 | 实现机制 |
|---|---|
| 高风险指令创建后冻结设备集合、参数摘要、有效窗口 | 创建即对 `sorted(devices) + canonical(params) + 窗口` 计算 SHA-256 摘要，设备集合/参数/窗口入库后不可变；第二角色确认时必须回传同一摘要 |
| 独立安全通道的第二角色确认 | 业务通道（8080，`X-Biz-Token`）与安全通道（8081，独立用户库 + 会话 Cookie）端口/凭据/网络完全分离；确认还要输入**带外送达的 6 位确认码**（只在创建响应出现一次，库存哈希） |
| 设备回执含启动代号与递增序号 | 设备每次启动生成随机高熵 `boot_code`，`seq` 从 1 起；网关按设备维护 `ledger_head_seq`，只接受 `head+1` |
| 旧启动代号不能改变当前状态 | `STALE_BOOT`：当前代号不匹配的回执/心跳直接拒绝，写入 `rejected_receipts`，状态不变 |
| 乱序回执不能改变当前状态 | `OUT_OF_ORDER_GAP`（跳号）、`REUSED_OR_OLD_SEQ`（序号复用）拒绝；完全相同的重复回执按幂等回放返回 `duplicate`，不重复落状态 |
| 事故恢复对账工单 | 服务重启后每个"已送达现场但缺终态回报"的目标幂等挂一张 `recovery_ticket`（表级唯一约束，重复扫描/重启不重复建单）；工单**只能从安全通道（8081）查看与处置**，业务/设备通道无此接口；窗口关闭时在途目标同样挂单 |
| 现场签名执行账簿 | HELLO 上传的每条账簿条目携带：**代次**(`boot_code`)、**单调编号**(`seq`)、**指令指纹**(`SHA256(command_id‖冻结摘要)`)、**代次内哈希链**(`prev→entry_hash`) 与设备密钥的**逐条 HMAC 签名**；任一不符只进 `ledger_quarantine` 隔离区留痕，绝不改状态 |
| 账簿四关校验 | ① 代次必须是该设备登记过的启动代号（旧/未知代号隔离）② 同代次 seq 严格 +1（缺口隔离，不臆补）③ entry_hash 重算一致且 HMAC 验签通过、command_id 确属网关投递且指纹吻合 ④ prev 与网关重放链头一致（断链隔离） |
| 重复上传幂等 | 已形成的事实重放返回 duplicate 不产生第二条事实；同一批次完全重复条目不隔离；同一坏材料重复上传隔离区只留一条痕（`entry_hash` 唯一） |
| 人工处置边界 | 安全员只能 ① 备注 ② 窗口仍有效时批准重投 ③ 过期后人工定 MISSED；**执行事实只能来自设备回执或校验通过的签名账簿，任何人工动作都不能写入/覆盖 EXECUTED/FAILED**；已确认事实上的工单对重投/MISSED 处置硬性 409 |
| 工作台证据透明 | `/tickets`、`/tickets/{id}` 展示每张工单的证据（指令/冻结摘要/投递代次/时间/窗口/既有回执）、冲突原因、append-only 处置历史与关联隔离材料；`/quarantine` 汇总全部隔离材料 |
| 撤销安全 | 已存在**任何执行事实**（EXECUTED/FAILED）→ 拒绝；已**在途**（DISPATCHED/DOUBT，是否执行不可证）→ 拒绝，必须先设备账本对账；只有从未到达设备的指令可撤销 |
| 确认超时 | 后台清扫 + 确认入口懒检查双保险；超时指令 `PENDING→EXPIRED`，目标 `SKIPPED`，设备永远拉取不到 |
| 网关重启不误执行 | 重启时所有"已投递无终态"目标转 `DOUBT` 并挂事故工单，**不做任何乐观重放**；等设备 HELLO 带签名账簿对账：已执行→补记事实（`LEDGER_RECOVERY`，工单 FACT_RECOVERED 结案），未执行且设备已换代号→窗口内才重投（工单留 REDELIVER 历史并随回执结案），窗口外→`MISSED`（工单 CLOSED_MISSED 结案） |
| 事实优先于过期结论 | 目标已被窗口结算为 MISSED 后，签名账簿补证当时已执行的，`recover_terminal` 改写为 EXECUTED/FAILED；工单重开、留 `FACT_RECOVERED_AFTER_MISSED` 痕迹后按事实结案 |
| 已执行事实不能被撤销覆盖 | `receipts` 表 `(command_id, device_id)` 唯一，目标终态 UPDATE 仅允许从在途态结算，终态之间互不可写；撤销接口与工单处置接口对存在执行事实的目标硬性拒绝 |
| 设备离线恢复 | 心跳超时置离线，离线设备 PULL 被拒；窗口内上线正常投递；窗口结束仍未投递记 `MISSED` 且事后上线也不再给指令 |
| 审计 | 所有变迁先在同一事务写 `events` 全序哈希链 `hash_n = SHA256(hash_{n-1}‖action‖payload)`；工单创建/系统动作/人工处置、隔离事件全部入链；工作台可一键重放校验，篡改任意一条即断链；被拒回执与隔离账簿分别单独留痕 |

状态机见 `dual_gateway/models.py` 顶部注释。

## 二、架构

```
   业务系统 (MES/调度)                第二角色 (安全员)                 现场设备/PLC
        │  业务通道 8080                    │  安全通道 8081              │  设备通道 8082
        │  X-Biz-Token                     │  口令+会话+带外确认码        │  HMAC-SHA256 设备密钥
        ▼                                  ▼                            ▼
  POST /api/commands               GET  /workbench                 POST /api/device/hello
  POST /api/commands/<id>/revoke   POST /api/commands/<id>/confirm      /api/device/heartbeat
  GET  /api/commands/...           POST /api/commands/<id>/reject       /api/device/pull
                                   GET  /tickets /tickets/<id>          /api/device/receipt
                                   POST /api/tickets/<id>/dispose
                                   GET  /quarantine
                                ┌──────────────────────────────┐
                                │  CommandService (单锁 + 事务)  │
                                │  状态机 / 签名账簿对账 /        │
                                │  事故工单 / 超时清扫           │
                                └──────────────┬───────────────┘
                                               ▼
                    SQLite: commands / targets / receipts /
                            rejected_receipts / device_boots /
                            recovery_tickets / ticket_actions /
                            ledger_quarantine /
                            events (哈希链) / devices
```

关键恢复语义：设备侧模拟器（`device_sim.py`）遵循真实 PLC 做法——
**执行前先把事实 fsync 写入本地 `ledger.jsonl`，再上送回执**。每条账簿记录
包含代次、单调编号、指令指纹、代次内哈希链与逐条 HMAC 签名。网关或链路任何
位置崩溃，设备重连 HELLO 时带账簿，网关用它与在途指令对账：

- 四关全部通过（代次/编号/指纹/连续性+签名）且账簿有、网关无回执（DOUBT/MISSED）
  → 补记 `LEDGER_RECOVERY`，**不重投、不双触发**，工单按事实结案；
- 设备已换 boot_code（确定重启过）且账簿无该指令 → 未执行是确定事实，窗口内
  重置为可投递；若本次上传含该目标的矛盾材料则保持 DOUBT 等安全员处置；
- 同 boot_code 但账簿无记录 → 是否正在执行未知，**保持 DOUBT 等待，绝不重投**；
- 编号缺口、断链、指纹不符、坏签名、未知/旧代次、网关从未投递、已撤销指令
  → 一律进入 `ledger_quarantine` 隔离区并在工单留冲突原因，绝不改状态；
- 同一事实/同一坏材料重复上传完全幂等。

## 三、快速开始

```bash
# 1. 启动网关（三个通道）
python3 -m dual_gateway.app
# 业务 http://127.0.0.1:8080  安全 http://127.0.0.1:8081  设备 http://127.0.0.1:8082

# 2. 打开安全工作台（第二角色）
#    http://127.0.0.1:8081/login
#    supervisor / S@fety-Confirm-7   （可确认/拒绝）
#    safety     / Audit-Readonly-9   （只读审计）

# 3. 启动模拟设备（真实 PLC 行为：账本 + 心跳 + 回执）
python3 -m dual_gateway.device_sim DEV-A1 --db ./data/sim
python3 -m dual_gateway.device_sim DEV-A2 --db ./data/sim
python3 -m dual_gateway.device_sim DEV-B1 --db ./data/sim

# 4. 业务系统创建高风险指令（返回的 confirm_code 走带外渠道交给第二角色）
curl -s -X POST http://127.0.0.1:8080/api/commands \
  -H 'X-Biz-Token: biz-token-ops-2026' -H 'Content-Type: application/json' \
  -d '{"action":"EMERGENCY_STOP","devices":["DEV-A1","DEV-A2"],
       "params":{"valve":"CLOSE","rpm":0},"valid_seconds":120}'

# 5. 第二角色在工作台输入确认码并复核摘要后确认；设备自动拉取执行并回执
# 6. 审计：工作台 /audit（哈希链校验）、/tickets（事故对账工单）、
#    /quarantine（隔离账簿）、/receipts（接受/拒绝回执）
```

一键观看全部攻击/故障场景（撤销边界、超时、旧代号、乱序、序号复用、
网关崩溃+回执丢失、设备重启、离线恢复、事故工单/签名账簿隔离、
人工处置边界、审计校验）：

```bash
python3 demo.py
```

设备模拟器故障注入开关：`--drop-receipt`（执行了但丢回执，考验账本补记）、
`--offline`（全程离线）、`--fail-rate 0.5`（随机执行失败）。

## 四、业务通道 API 摘要

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/commands` | 创建并冻结指令；响应一次性返回 `confirm_code` |
| GET | `/api/commands?status=` | 列表 |
| GET | `/api/commands/{id}` | 详情（含每个设备目标状态与回执） |
| POST | `/api/commands/{id}/revoke` | 撤销（受上述硬约束） |

设备通道全部 POST JSON，头部 `X-Device-Id` + `X-Signature: HMAC_SHA256(key, body)`：
`/api/device/hello`（含 `boot_code`、`first_seq`、`ledger`；每条账簿条目含
`entry_hash`/`prev`（代次内哈希链）、`fingerprint`（指令指纹）、`signature`
（设备密钥对 entry_hash 的 HMAC））、
`/heartbeat`、`/pull`、`/receipt`（`boot_code,seq,command_id,result,message`）。
HELLO 响应中的 `ledger` 字段返回 `recovered / duplicates / quarantined` 对账计数。

安全通道 JSON（会话 Cookie；事故恢复能力**只存在于安全通道**）：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/tickets?status=OPEN\|RESOLVED` | 事故恢复对账工单列表（safety/supervisor 可查） |
| GET | `/api/tickets/{id}` | 工单证据、冲突原因、处置历史、关联隔离材料 |
| POST | `/api/tickets/{id}/dispose` | 仅 supervisor：`MANUAL_NOTE` / `APPROVE_REDELIVER`（窗口内）/ `CLOSED_MISSED`（过期后） |
| GET | `/api/quarantine?device=` | 账簿隔离区（缺口/矛盾/旧代次/坏签名等留痕） |

浏览器页面：`/tickets`（工单列表，含挂起/已解决/全部视图）、`/tickets/{id}`
（证据卡 + 冲突横幅 + 处置表单 + 处置历史 + 关联隔离材料）、`/quarantine`。

## 五、运行测试

```bash
python3 -m unittest tests.test_service -v   # 领域规则单元测试（含工单/隔离/处置边界）
python3 -m unittest tests.test_e2e    -v   # 真实三端口 HTTP + 进程级重启端到端
```

## 六、生产化备注（本实现未做、真实部署必须做的事）

- 三通道分别绑定独立网卡/网段并加 mTLS 或专线；本实现用端口隔离演示；
- 设备密钥经 KMS/烧录下发并支持轮换；确认码接真实带外通道（硬令牌/语音）；
- SQLite 可替换为 Postgres（接口已集中在 `storage.py`），多实例时用其行锁/SELECT FOR UPDATE；
- 工作台前置于企业 SSO + 强 MFA，会话 Cookie 加 Secure；
- 审计事件链增加每日锚点（发布到独立 WORM/时间戳服务），防止整库离线篡改。
