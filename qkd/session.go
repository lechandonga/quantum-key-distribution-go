package qkd

import (
	"fmt"
	"time"
)

// SecurityLevel 表示密钥登记/取用所需的安全等级。等级越高要求越强。
type SecurityLevel int

const (
	SecurityStandard SecurityLevel = 1
	SecurityEnhanced SecurityLevel = 2
)

// Stats 是一次会话对外暴露的全部细节：仅含阶段名与聚合统计量，
// 刻意不包含任何原始比特、抽样位置或密钥材料。
type Stats struct {
	PhotonsPrepared int
	PhotonsDetected int
	SiftedBits      int
	SampleBits      int
	SampleErrors    int
	QBER            float64
	ReconcileLeak   int // 纠错公开奇偶比特数
	ConfirmLeak     int // 一致性校验泄露上界
	SampleLeak      int // 抽样公开比特数
	TotalLeak       int
	SecurityBits    int
	FinalKeyBits    int
	Duration        time.Duration
}

// Session 是一次 BB84 会话的只读结果视图。
type Session struct {
	ID            string
	Seed          uint64
	Aborted       bool
	AbortReason   FailReason
	SecurityLevel SecurityLevel
	Stats         Stats

	KeyID string // 成功时对应的密钥标识；中止会话为空
}

// execute 执行一次完整的 BB84 仿真会话（同步、确定性）。
// 成功时返回会话视图与最终密钥材料；中止时材料为 nil，且不会产生密钥。
func execute(cfg Config, securityLevel SecurityLevel, logger Logger) (*Session, []byte, error) {
	c := cfg.withDefaults()
	sid := fmt.Sprintf("s%016x", c.Seed)
	if logger == nil {
		logger = NopLogger()
	}
	if err := c.validate(); err != nil {
		logger.Warnf(sid, "session aborted stage=config reason=%s", ReasonOf(err))
		return nil, nil, err
	}

	start := time.Now()
	s := &Session{ID: sid, Seed: c.Seed, SecurityLevel: securityLevel}
	st := &s.Stats

	abort := func(reason FailReason, format string, args ...any) (*Session, error) {
		s.Aborted = true
		s.AbortReason = reason
		s.Stats.Duration = time.Since(start)
		logger.Warnf(sid, "session aborted reason=%s %s", reason, fmt.Sprintf(format, args...))
		return s, fail(reason, format, args...)
	}

	// 1) 制备
	aliceRng := newBitStream(c.Seed, 1)
	chRng := newBitStream(c.Seed, 2)
	bobRng := newBitStream(c.Seed, 3)
	sampleRng := newBitStream(c.Seed, 4)

	ps := prepare(c.Photons, aliceRng)
	senderBits := make([]byte, c.Photons)
	senderBases := make([]byte, c.Photons)
	for i := range ps {
		senderBits[i] = ps[i].bit
		senderBases[i] = ps[i].basis
	}
	st.PhotonsPrepared = c.Photons
	logger.Infof(sid, "stage=prepare photons=%d", c.Photons)

	// 2) 量子信道传输
	transmit(ps, c, chRng)
	detected := 0
	for i := range ps {
		if ps[i].detected {
			detected++
		}
	}
	st.PhotonsDetected = detected
	logger.Infof(sid, "stage=channel detected=%d eavesdrop=%t loss=%.3f noise=%.3f",
		detected, c.Eavesdrop, c.Loss, c.Noise)

	// 3) 接收测量
	measure(ps, bobRng)

	// 4) 基矢筛选
	alice, bob := sift(senderBits, senderBases, ps)
	st.SiftedBits = len(alice)
	logger.Infof(sid, "stage=sift sifted_bits=%d", len(alice))
	if len(alice) < c.MinSifted {
		es, err := abort(ReasonTooFewSamples,
			"sifted bits %d below minimum %d (channel loss too high?)", len(alice), c.MinSifted)
		return es, nil, err
	}

	// 5) 抽样误码率估计
	sampleCount := int(float64(len(alice))*c.SampleFraction + 0.999999) // 向上取整
	if sampleCount >= len(alice) {
		sampleCount = len(alice) - 1
	}
	if sampleCount < c.MinSamples {
		es, err := abort(ReasonTooFewSamples,
			"sample size %d below minimum %d", sampleCount, c.MinSamples)
		return es, nil, err
	}
	alice, bob, sr := estimateQBER(alice, bob, sampleCount, sampleRng)
	st.SampleBits, st.SampleErrors, st.QBER = sr.sampleSize, sr.errors, sr.qber
	st.SampleLeak = sr.sampleSize
	logger.Infof(sid, "stage=sampling sample_bits=%d errors=%d qber=%.4f",
		sr.sampleSize, sr.errors, sr.qber)
	if sr.qber > c.QBERThreshold {
		es, err := abort(ReasonQBERExceeded,
			"estimated QBER %.4f exceeds threshold %.4f", sr.qber, c.QBERThreshold)
		return es, nil, err
	}

	// 6) 纠错（Cascade）+ 一致性校验
	_, blockLeak, err := reconcile(alice, bob, c.Seed, c.Faults, logger, sid)
	st.ReconcileLeak = blockLeak
	st.ConfirmLeak = c.ConfirmLeakBits
	if err != nil {
		st.TotalLeak = st.SampleLeak + blockLeak + c.ConfirmLeakBits
		es, aerr := abort(ReasonOf(err), "reconciliation failed: %v", err)
		return es, nil, aerr
	}

	// 7) 泄露核算与密钥长度计算
	// 最终长度 = 纠错后码长 - 抽样泄露 - 纠错泄露 - 校验泄露 - 安全参数
	totalLeak := st.SampleLeak + blockLeak + c.ConfirmLeakBits
	st.TotalLeak = totalLeak
	st.SecurityBits = c.SecurityBits
	remaining := len(alice) - totalLeak - c.SecurityBits
	if remaining < 8 {
		es, err := abort(ReasonKeyTooShort,
			"usable key length %d bits after leakage %d and security %d is too small",
			remaining, totalLeak, c.SecurityBits)
		return es, nil, err
	}

	// 8) 隐私放大
	paRng := newBitStream(c.Seed, 5)
	paSeed := paRng.pcg.Uint64()
	finalBits := toeplitzExtract(alice, remaining, paSeed)
	keyMaterial := bitsToBytes(finalBits)
	st.FinalKeyBits = remaining
	s.Stats.Duration = time.Since(start)
	logger.Infof(sid, "stage=privacy_amplification final_key_bits=%d duration=%s",
		remaining, s.Stats.Duration)

	return s, keyMaterial, nil
}
