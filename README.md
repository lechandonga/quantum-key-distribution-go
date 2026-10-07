# BB84 量子密钥分发仿真组件（Go，纯标准库）

本仓库用软件完整模拟 BB84 协议的一次会话：发送方制备光子、量子信道
（损耗 / 噪声 / 可选全程窃听）、接收方测量、基矢筛选、抽样误码率
（QBER）估计、Cascade 风格纠错、一致性校验、隐私放大，以及会话与
一次性密钥的集中管理。**不依赖任何外部服务、真实设备或凭据，仅使用
Go 标准库。**

> 安全说明：这是教学/仿真模型，不提供任何真实的量子安全保证。所有
> “量子”行为都是经典软件对理想 BB84 与拦截-重发攻击的统计建模。

## 目录结构

| 路径 | 职责 |
| --- | --- |
| `qkd/config.go` | 会话参数、默认值与参数校验 |
| `qkd/quantum.go` | 光子制备、信道（损耗/噪声/窃听）、测量、基矢筛选 |
| `qkd/reconcile.go` | 抽样 QBER 估计、Cascade 纠错、奇偶泄露计数 |
| `qkd/privacy.go` | 一致性哈希、Toeplitz 通用哈希隐私放大、比特打包 |
| `qkd/session.go` | 会话主流程、阶段统计、密钥长度核算、失败原因 |
| `qkd/manager.go` | 并发安全的会话管理器与一次性密钥池 |
| `qkd/errors.go` | 可区分的失败原因（`FailReason`） |
| `qkd/logger.go` | 最小日志接口（只允许阶段名与聚合统计） |
| `qkd/rng.go` | 基于 `math/rand/v2` PCG 的确定性可复现随机流 |
| `cmd/bb84-demo` | 正常 / 被窃听 / 高损耗三种场景的本地演示 |

## 协议流程

1. **制备（prepare）**：发送方为每个光子独立随机生成经典比特与
   基矢（Z 或 X）。
2. **量子信道（channel）**：
   - 以 `Loss` 概率丢弃光子（模拟损耗/探测器无响应）；
   - `Eavesdrop=true` 时，窃听者对每个光子随机选基测量并按测量结果
     重发（拦截-重发）。选错基时测量结果坍缩为随机值，因此在双方
     基矢一致的位置上以 1/2 概率引入翻转，**筛后码串 QBER 约 25%**；
   - 存活光子以 `Noise` 概率被翻转比特（独立去极化噪声）。
3. **测量（measure）**：接收方对存活光子随机选基测量；测量基与
   偏振基不一致时结果随机坍缩。
4. **基矢筛选（sift）**：双方在（假设已认证的）经典信道上对比基矢，
   仅保留基矢一致且探测成功的位置。筛后码长低于 `MinSifted` 即中止。
5. **抽样估计（sampling）**：按 `SampleFraction` 由确定性置换抽出
   位置并公开比对，得到样本 QBER；抽样比特永久剔除。样本数低于
   `MinSamples` 或 QBER 高于 `QBERThreshold` 即中止。
6. **纠错（reconcile）**：Cascade 风格的多轮置换 + 定长块（8/64/512）
   奇偶公开与二分纠错，必要时重复置换扫描，直到确认通过。每公开
   **1 个奇偶值 = 1 比特泄露**，全程累计为 `ReconcileLeak`。
7. **一致性校验（confirm）**：双方对纠错后码串计算带域分隔的
   SHA-256 摘要比对；不一致立即中止（故障注入
   `Faults.FlipAfterReconcile` 可复现该场景），绝不放行可能不一致的
   密钥。该步骤泄露上界记为 `ConfirmLeakBits`（默认 256）。
8. **密钥长度核算**：

   ```
   FinalKeyBits = 纠错后码长
                - SampleLeak        （抽样公开的比特数）
                - ReconcileLeak     （纠错公开的奇偶比特数）
                - ConfirmLeakBits   （一致性校验泄露上界）
                - SecurityBits      （安全参数）
   ```

   结果不足 8 比特时以 `key_too_short` 明确拒绝，不产出空/短密钥。
9. **隐私放大（privacy amplification）**：以公开种子构造的 Toeplitz
   矩阵通用哈希（剩余熵提取器）输出最终比特，MSB-first 打包为字节。

## 参数含义与安全边界

| 参数 | 默认 | 含义与边界 |
| --- | --- | --- |
| `Seed` | 必填 | 确定性种子。同种子 + 同参数各阶段统计与最终密钥逐字节一致 |
| `Photons` | 必填 | 制备光子数，至少 2 |
| `Loss` | — | 丢光概率，范围 `[0,1)`；过高会触发 `too_few_samples` |
| `Noise` | — | 比特翻转概率，范围 `[0,1)`；QBER 超阈即中止 |
| `Eavesdrop` | `false` | 是否开启全程拦截-重发窃听（筛后 QBER≈25%，稳定检出） |
| `SampleFraction` | `0.2` | 抽样比例 `(0,1)`；比例越大估计越可靠，但 `SampleLeak` 越大 |
| `QBERThreshold` | `0.12` | QBER 安全阈值 `(0,1)`；**注意仿真模型中噪声/窃听到筛后 QBER 的映射是简化的，阈值不对应任何现实工程门限** |
| `MinSifted` | `256` | 筛后最小码长，低于即中止 |
| `MinSamples` | `64` | 最小有效抽样数，低于即中止（小样本统计不可信） |
| `ConfirmLeakBits` | `256` | 一致性校验泄露上界；按 SHA-256 摘要长度保守取值 |
| `SecurityBits` | `128` | 安全参数比特，统一从密钥长度中扣除（覆盖提取器失败概率与统计涨落的保守余量） |

关于泄露上界：本仿真对信息协调采用“公开多少奇偶就计多少比特”的
如实记账，再加上固定的校验摘要上界与安全参数。它**不是**针对通用
量子攻击的严格信息论安全证明（现实系统还需考虑有限码长分析、
Eve 的侧信道、探测器漏洞等），只是一个自洽、保守且可审计的工程
模型。

## 失败原因（可程序化区分）

| `FailReason` | 触发条件 |
| --- | --- |
| `invalid_config` | 参数越界或组合非法 |
| `too_few_samples` | 筛后码长不足或有效样本不足 |
| `qber_exceeded` | 抽样 QBER 超过阈值（窃听/高噪声） |
| `reconcile_hash_mismatch` | 纠错后一致性校验失败 |
| `key_too_short` | 扣除全部泄露与安全参数后密钥过短 |
| `key_unknown` / `key_consumed` / `security_level_too_high` | 取用未知 / 已消费 / 等级不足的密钥 |
| `pool_exhausted` | 密钥池没有满足等级的可用密钥 |
| `session_aborted` | 引用未知会话 |

中止的会话不会产生任何可领取密钥。

## 使用示例

```go
mgr := qkd.NewManager(qkd.NewStdLogger())

s, err := mgr.Run(qkd.Config{
    Seed: 42, Photons: 20000,
    Loss: 0.1, Noise: 0.01, Eavesdrop: false,
}, qkd.SecurityStandard)
if err != nil {
    // qkd.ReasonOf(err) 给出可区分原因
    log.Fatal(qkd.ReasonOf(err))
}

key, err := mgr.Acquire(s.KeyID, qkd.SecurityStandard) // 一次性
// 或 mgr.AcquireAny(qkd.SecurityStandard)
```

## 本地验证与复现

```bash
# 演示正常 / 窃听 / 高损耗三种会话
go run ./cmd/bb84-demo

# 全量单测（建议开启竞态检测；需要 CGO）
CGO_ENABLED=1 go test ./... -race -v

# 不带竞态的快速运行
go test ./... -v
```

`-v` 输出中每条用例都会打印“业务覆盖: …”说明，便于核对覆盖的业务
点。测试覆盖：正常会话、窃听稳定检出与干净信道不误判、噪声梯度、
校验失败、样本不足、非法参数、密钥过短拒绝、种子可复现、大码长
（筛后十万比特级，单次约 0.2~0.7 秒）、小码长、并发会话与并发争抢
同一密钥（16 争抢者 × 10 轮，恰有一人成功）、密钥池各类拒绝原因，
以及日志不包含任何密钥片段。

复现某次会话：使用相同的 `Config`（含 `Seed`）再次调用
`Manager.Run`，两个会话实例相互独立，但各阶段统计（耗时除外）与
最终密钥材料完全一致。
