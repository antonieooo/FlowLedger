# SCHEMA-DELTA v1alpha5 (2026-08-24)

`v1alpha4` → `v1alpha5`. **纯新增。** 既有 197 个 JSON 键的名、类型、语义、分桶边界、
窗口逻辑、窗长全部逐字不变；新增 14 个键。

机器判据：`pkg/ledger/schema_delta_v1alpha5_test.go::TestSchemaDeltaIsAdditiveOnly`
把序列化后的 `Record` 键集与**从冻结语料 B 实际读出**的 v1alpha4 键集比对
（`/mnt/…/adopted-corpus/unit-1/raw-fl-worker.jsonl.gz` 前 2 万条，197 键），
只允许下表这 14 个新增，少一个既有键或多一个未申报键都判 FAIL。键集取自语料而非本仓结构体，
所以它不会跟着被它监管的代码一起漂。

采集器分支 `collector-v1alpha5-direction-split`，镜像 `flowledger-node-agent:v1a5e0`。

---

## 1. 新增字段清单

### 1.1 包长直方图（方向拆分）

| 键 | 类型 | 语义 |
|---|---|---|
| `pkt_size_histogram_out` | `map[string]uint64 \| null` | 出向（本机 egress）包长直方图 |
| `pkt_size_histogram_in` | `map[string]uint64 \| null` | 入向（本机 ingress）包长直方图 |

- 桶边界：**与既有 `pkt_size_histogram` 同一张表**，7 桶
  `0-63 / 64-127 / 128-255 / 256-511 / 512-1023 / 1024-1500 / >1500`，
  度量同为 `skb->len`。Go 侧两者由**同一个** `ebpfPacketSizeHistogramBuckets` 切片贴标签
  （`TestDirectionalHistogramsShareBucketLabels` 钉住）。
- 语义同既有：`window_summary` 上是窗口增量，`session_summary` 上是全连接累计。

**恒等式（硬保证，逐桶）**
```
pkt_size_histogram_out[b] + pkt_size_histogram_in[b] == pkt_size_histogram[b]
Σ_b pkt_size_histogram_out[b] == observed_skb_packets_out
Σ_b pkt_size_histogram_in[b]  == observed_skb_packets_in
```
成立原因：内核在 `update_packet_stats` 的**同一调用点**、同一个 `pkt_bucket` 下，
对混合数组和方向数组各做一次 `__sync_fetch_and_add`；`real_packets_sent/recv`
（即 `observed_skb_packets_out/in`）在同一函数里由**同一个 `ingress` 参数**选择。
混合数组**没有**被改写成 `out+in` 的派生量——三份累加保持独立，恒等式才是真检验而不是恒真式。

### 1.2 IAT 直方图（方向拆分）

| 键 | 类型 | 语义 |
|---|---|---|
| `iat_histogram_out` | `map[string]uint64 \| null` | 出向**方向内**相邻包间隔直方图 |
| `iat_histogram_in` | `map[string]uint64 \| null` | 入向**方向内**相邻包间隔直方图 |

- 桶边界：与既有 `iat_histogram` 同一张表，6 桶（µs）
  `<100 / 100-1000 / 1000-10000 / 10000-100000 / 100000-1000000 / >1000000`。

**⚠ 与任务书 §3 判词相反：IAT 也有精确加法恒等。**
```
iat_histogram_out[b] + iat_histogram_in[b] == iat_histogram[b]
```
任务书假设混合版的「相邻」是跨方向交错的，因此方向版是不可对加的新量。
**对本采集器为假。** `update_packet_stats` 从 v1alpha3 起就一直拿
`last_packet_ns_sent` / `last_packet_ns_recv` 做差——即「**同方向**上一个包」——
再把结果并进一个共享数组。所以既有的混合 IAT 直方图从来就是两个方向内直方图之和，
拆开是无损分解，不是新量。代码注释按实测写，不按判词写。

（这条改变了任务书对该字段族的定性，是本轮最该带回上位文档的一条。）

### 1.3 TTL 极值（方向拆分）

| 键 | 类型 | 语义 |
|---|---|---|
| `ip_ttl_min_out` / `ip_ttl_max_out` | `uint32 \| null` | 出向 TTL 极值 |
| `ip_ttl_min_in` / `ip_ttl_max_in` | `uint32 \| null` | 入向 TTL 极值 |

- 滚动语义与既有 `ip_ttl_min/max` **完全一致**：按 flow_stats 条目生命周期累计，
  **不按窗重置**（「按窗重置」未批，未做），窗口无效时也不清零（它们是包络不是增量）。
- 同为「并发尽力而为极值」（非原子 compare-then-store，可能丢一次更新），与既有一致。
- 受 `collect_header_aggregates` 开关管辖，与既有 TTL 同一个门（当前部署为 `true`）。
- `null` = 该方向没观测到包（TTL 0 在线上非法，所以 0 无歧义）。

### 1.4 TCP 标志「包」计数（方向拆分）

| 键 | 类型 | 语义 |
|---|---|---|
| `syn_count_out` / `syn_count_in` | `uint64` | 窗内该方向**带 SYN 位的包数** |
| `fin_count_out` / `fin_count_in` | `uint64` | 同，FIN |
| `rst_count_out` / `rst_count_in` | `uint64` | 同，RST |

- 读取点：`cgroup_skb` 的 phase-B TCP 头字节 12..15 加载处，与 `tcp_flags_or_sent/recv`
  **同一次加载、同一个方向指针**；`__sync_fetch_and_add` 原子累加。
- 位定义 `FIN=0x01 / SYN=0x02 / RST=0x04`。一个包带多个标志（SYN+ACK、FIN+ACK、RST+ACK）
  会各自 +1 —— 这是**「带该标志的包数」，不是 TCP 事件数**。
- 受 `collect_header_aggregates` 管辖（需要那次 TCP 头加载）。
- 窗口语义同其他累加计数：`window_summary` 是增量，`session_summary` 是累计。

**⚠ 这不是既有 `syn_count`/`fin_count`/`rst_count` 的分解。**
既有三个是**逐连接**量，由 `inet_sock_set_state` 追踪点写：
`syn_count = 1`（ESTABLISHED 那一刻）、`fin_count += 1`（TCP_CLOSE）、
`rst_count` **从来不写**。语料 B 实测印证：331,845 条 window 上 `syn_count ∈ {0,1}`、
`fin_count ∈ {0,1}`、`rst_count ≡ 0`。
所以：一次 SYN 重传让 `syn_count_out` +1 而 `syn_count` 不动；对端 SYN+ACK 让 `syn_count_in` +1。
**既有 `rst_count` 保持不点火**（默认项），旧结论对新数据继续成立，有单元测试钉住。

---

## 2. `null` 纪律（重要）

四个方向直方图与四个方向 TTL **一律不配 `*_available` 标志**（任务书禁令），
因此 `null` 是它们唯一的「无读数」通道，含义被钉死为：

| 取值 | 含义 |
|---|---|
| `null` | 该方向在本流上**从未被观测**，或本条 `window_valid=false` |
| 全 0 的 map | 该方向**确实在观测中**，只是本窗没有包（长连接的安静窗口） |

绝不用「全 0 直方图」冒充未观测——那等于声称做过一次并不存在的测量。
`window_valid=false` 时四个方向直方图置 `null`、六个方向计数置 0、四个 TTL 保留
（与既有 `ip_ttl_min/max` 在无效窗上的行为一致）。

## 3. 覆盖边界（结构性，必须随字段一起读）

包路径只有在 `canonical_key_from_skb` 命中 `local_ep_to_key` 时才会走到，
而该索引**只在连接到达 ESTABLISHED 时建立**（`index_local_ep`，以及已建连流的首次
`tcp_sendmsg/recvmsg`）。因此：

- **建连后的 RST 可见**：服务端重置、空闲超时重置、异常断开 → `rst_count_in > 0`。✅
- **闭端口拒连不可见**：SYN → RST 全程未 ESTABLISHED，无 flow_stats 条目，
  两个包都计入 `DROP_PACKET_EP_MISS`，**不进入任何记录**。❌
- **SYN 无应答不可见**：同上机制。❌

即：`rst_count_in` 回答的是「**已建立的连接被重置了吗**」，
**不是**「有人在扫闭端口吗」。失败的连接尝试在 v1alpha5 下仍然只以
v1alpha4 早就有的形态出现——零流量的 `session_summary`（语料 B：68,155 条里 728 条，1.07%）
与 `window_invalid_reason="unknown_baseline"` 的窗口（4.1%）。

要覆盖扫描/拒连场景，必须新增建条目时机（SYN_SENT）——那会改动流生命周期与
`conn_start_time`/window 人口，**本轮已就此上报并由 Holden 拍板不做（方案 A）**。

## 4. 资源代价

| 项 | v1alpha4 | v1alpha5 | 说明 |
|---|---|---|---|
| `struct flow_stats` | 360 B | 600 B | ×65536 条 = **22.5 MiB → 37.5 MiB** 内核内存/节点 |
| `struct flow_event` | 360 B | 600 B | 16 MiB ringbuf 可容 ~46.6k → ~27.9k 在途事件 |
| 新增 map | — | `flow_stats_init_scratch` | per-CPU array ×1 条 |

- `flow_stats` 超过 512 B 的 BPF 栈上限，故 `struct flow_stats init = {}` 的栈实例
  改为 per-CPU array 暂存（`zeroed_stats_template()`）。仅建条目路径使用，**不在包路径上**。
- 直方图保持 `u64` 而非压成 `u32` 去挤回旧预算：`u32` 在超长流上可能先于混合数组溢出，
  会**静默破坏加法恒等**。
- 两个尺寸预算门（`TestBPFStructResourceBudget`、`TestAuditEBPFResources`）
  已从 384/376 显式上调到 608，附算术与理由——不是被顺手改绿的。

## 5. 变更文件

```
bpf/flow_events.bpf.c                   +260/-  (字段、单一方向拆分点、栈修复)
pkg/collector/collector.go              +36     (FlowEvent)
pkg/collector/ebpf_event.go             +49     (rawEBPFEvent 线格式 + 转换)
pkg/collector/flowevents_{x86,arm64}_bpfel.{go,o}   (bpf2go 重新生成)
pkg/features/features.go                +8      (SchemaVersion → v1alpha5)
pkg/ledger/writer.go                    +168    (Record + 填充；含 gofmt 空白对齐)
pkg/sessionizer/sessionizer.go          +172    (会话态、窗口差分、baseline、合并)
```
测试：`ebpf_event_v1alpha5_test.go`(7) · `direction_split_v1alpha5_test.go`(7) ·
`schema_delta_v1alpha5_test.go`(2) 新增 16 个；既有 `ebpf_event_test.go`、
`ebpf_layout_test.go`、`resource_audit_test.go` 的偏移/预算断言按新布局更新。

> `git diff -w` 在 Go 侧**零删除行**——`writer.go`/`sessionizer.go` 在 HEAD 上本来就不是
> gofmt-clean，本轮的删除行全是空白重排，无一处既有语义改动。
