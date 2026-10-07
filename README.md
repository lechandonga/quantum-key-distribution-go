# quantum-key-distribution-go

纯 Go 标准库实现的本地 BB84 量子密钥分发（QKD）仿真。用软件模拟发送方
（Alice）、量子信道（可配置损耗 / 噪声 / 窃听）、接收方（Bob）与集中式
密钥池之间的完整会话，不依赖任何外部服务、真实设备或凭据。

## 协议流程

每次会话（`Manager.RunSession`）依次执行：

1. **光子制备与传输**：Alice 生成随机比特与随机基矢；信道按 `ChannelLoss`
   丢弃光子、按 `ChannelNoise` 翻转比特；开启 `Eavesdrop` 时 Eve 对每个光子
   做随机基矢拦截-重发（在筛选后密钥上引入约 25% 误码）。
2. **基矢筛选**：只保留"光子到达且双方基矢一致"的位置。
3. **抽样误码率估计**：从筛选后密钥中随机抽取 `SampleRatio` 比例的比特公开
   比对。样本量小于 `MinSample` 时以 `ErrInsufficientSample` 中止；估计 QBER
   超过 `QBERThreshold` 时以 `ErrQBERExceeded` 中止（窃听检测）。抽样比特
   已公开，从密钥中移除。
4. **纠错（CASCADE）**：多轮公开洗牌 + 倍增块大小的奇偶校验二分纠错，带
   回溯。每一个公开的奇偶比特都计入 `LeakEC`。
5. **一致性校验**：双方交换 `SHA-256(nonce || key)` 的截断标签
   （`SecurityParam` 比特）。不一致则以 `ErrVerificationFailed` 中止，绝不
   输出可能不一致的密钥。标签比特计入 `LeakVerify`。
6. **隐私放大**：最终密钥长度
   `m = floor(n·(1 − h2(QBER))) − LeakEC − LeakVerify − SecurityParam`
   （向下取整到字节）。`m <= 0` 时以 `ErrInsufficientKeyMaterial` 明确拒绝，
   不会给出短密钥或空密钥。提取器为带公开种子的 SHA-256 计数器模式泛哈希。
7. **密钥入库**：成功会话的最终密钥存入 `KeyPool`，登记唯一 ID 与安全等级
   （最终密钥比特数）。中止的会话不会留下任何可取用的密钥。

## 参数与安全边界

| 参数 | 含义 | 合法范围 / 说明 |
| --- | --- | --- |
| `NumQubits` | Alice 制备的光子数 | ≥ 64；十万比特以上输入亦可在线性时间内完成 |
| `Seed` | 主随机种子 | 同一组参数 + 种子完全复现各阶段统计与最终密钥 |
| `ChannelLoss` | 信道损耗概率 | [0,1)；只减少收光数，不影响误码 |
| `ChannelNoise` | 信道比特翻转概率 | [0,0.5)；正常信道应远低于阈值 |
| `Eavesdrop` | 是否开启拦截-重发窃听 | 全程窃听使 QBER≈25%，被稳定检出 |
| `SampleRatio` | 抽样比例 | (0,1)；越大估计越准但剩余密钥越短 |
| `MinSample` | 最小有效样本量 | 低于即中止，避免小样本误码率失真 |
| `QBERThreshold` | 误码率安全阈值 | (0,0.5)；常用 0.11（BB84 理论界附近） |
| `SecurityParam` | 安全参数（比特） | [16,512]；同时作为校验标签长度与隐私放大安全余量 |

泄露上界：公开信息量 = `LeakEC`（纠错奇偶比特）+ `LeakVerify`（校验标签），
隐私放大在 `n·(1−h2(QBER))` 的熵预算中如实扣除这两项与 `SecurityParam`，
扣完不足即拒绝。参数组合非法时 `Params.Validate` 返回 `ErrInvalidParams`。

## 密钥池语义

- 每把密钥有唯一 ID，登记生成时的安全等级（最终密钥比特数）。
- `Take(id, requiredLevel)` 原子取用，每把密钥只能取一次：
  - 未知 ID → `ErrKeyNotFound`
  - 重复取用 → `ErrKeyAlreadyConsumed`
  - 要求等级高于登记值 → `ErrInsufficientSecurityRank`
- `TakeAny(requiredLevel)` 无可满足密钥 → `ErrPoolEmpty`。
- 并发取用时同一把密钥只会发给一个使用方（竞态检测下验证）。

## 日志

日志只包含会话编号、阶段名与计数器（收光数、筛选长度、QBER、泄露量、
最终长度等），绝不输出原始比特、抽样内容或密钥材料；有对应单测守护。

## 本地验证与复现

```sh
# 运行全部单测（含竞态检测）
CGO_ENABLED=1 go test -race -v ./qkd/

# 正常会话（确定性：相同 -seed 结果完全一致）
go run ./cmd/qkdsim -seed 42

# 全程窃听：稳定以 QBER 超限中止
go run ./cmd/qkdsim -eve
```

测试覆盖：正常会话、不同噪声与窃听检测、校验失败、样本不足、非法参数、
并发会话互不干扰、并发/重复取用、安全等级与池耗尽、参数与种子可复现、
小/中/大（20 万比特）码长、日志不泄露密钥材料。`go test -v` 的输出中
每个用例都打印了覆盖的业务场景说明。

## 目录结构

- `qkd/` — 核心库：会话各阶段、纠错、隐私放大、密钥池、会话管理器
- `cmd/qkdsim/` — 命令行演示程序
