package qkd

import "math"

// Config 描述一次 BB84 仿真会话的全部可调参数。
//
// 协议安全相关量：
//   - SampleFraction: 从筛选后码串中抽出做误码率估计的比例；
//   - QBERThreshold: 抽样误码率（0~1）的安全阈值，超过即中止；
//   - SecurityBits: 隐私放大额外扣除的安全参数比特（覆盖通用哈希的
//     -log2 ε 项，统一从密钥长度中保守扣除）；
//   - ConfirmLeakBits: 纠错后一致性哈希校验所公开的信息量上界（比特）。
type Config struct {
	// Seed 为确定性随机种子；相同 Seed + 参数下各阶段结果与最终密钥一致。
	Seed uint64
	// Photons 发送方制备的光子（脉冲）总数。
	Photons int

	// Loss 信道损耗概率 [0,1)：光子以该概率丢失（探测器无响应）。
	Loss float64
	// Noise 信道噪声概率 [0,1)：存活光子携带的比特被翻转的概率。
	Noise float64
	// Eavesdrop 开启后模拟全程拦截-重发窃听。
	Eavesdrop bool

	// SampleFraction 抽样比例 (0,1)。
	SampleFraction float64
	// QBERThreshold 误码率安全阈值 (0,1)。
	QBERThreshold float64

	// MinSifted 基矢筛选后允许的最小码长。
	MinSifted int
	// MinSamples 抽样估计允许的最小有效样本数。
	MinSamples int

	// ConfirmLeakBits 一致性校验公开信息量上界（默认 256，见 SHA-256）。
	ConfirmLeakBits int
	// SecurityBits 隐私放大安全参数（默认 128）。
	SecurityBits int

	// Faults 测试用故障注入开关（默认全关）。
	Faults Faults
}

// Faults 用于构造一致性校验失败等边界场景，正常使用保持零值。
type Faults struct {
	// FlipAfterReconcile 在接收端纠错完成、校验之前翻转 1 个比特。
	FlipAfterReconcile bool
}

func (c Config) withDefaults() Config {
	if c.SampleFraction == 0 {
		c.SampleFraction = 0.2
	}
	if c.QBERThreshold == 0 {
		c.QBERThreshold = 0.12
	}
	if c.MinSifted == 0 {
		c.MinSifted = 256
	}
	if c.MinSamples == 0 {
		c.MinSamples = 64
	}
	if c.ConfirmLeakBits == 0 {
		c.ConfirmLeakBits = 256
	}
	if c.SecurityBits == 0 {
		c.SecurityBits = 128
	}
	return c
}

func (c Config) validate() error {
	check := func(cond bool, msg string) error {
		if cond {
			return fail(ReasonInvalidConfig, "%s", msg)
		}
		return nil
	}
	if err := check(c.Photons < 2, "Photons must be at least 2"); err != nil {
		return err
	}
	if err := check(c.Loss < 0 || c.Loss >= 1, "Loss must be in [0,1)"); err != nil {
		return err
	}
	if err := check(c.Noise < 0 || c.Noise >= 1, "Noise must be in [0,1)"); err != nil {
		return err
	}
	if err := check(c.SampleFraction <= 0 || c.SampleFraction >= 1, "SampleFraction must be in (0,1)"); err != nil {
		return err
	}
	if err := check(c.QBERThreshold <= 0 || c.QBERThreshold >= 1, "QBERThreshold must be in (0,1)"); err != nil {
		return err
	}
	if err := check(math.IsNaN(c.Loss+c.Noise+c.SampleFraction+c.QBERThreshold), "parameters must not be NaN"); err != nil {
		return err
	}
	if err := check(c.MinSifted <= 0, "MinSifted must be positive"); err != nil {
		return err
	}
	if err := check(c.MinSamples <= 0, "MinSamples must be positive"); err != nil {
		return err
	}
	if err := check(c.ConfirmLeakBits < 0, "ConfirmLeakBits must be non-negative"); err != nil {
		return err
	}
	if err := check(c.SecurityBits < 0, "SecurityBits must be non-negative"); err != nil {
		return err
	}
	return nil
}
