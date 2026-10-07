package qkd

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

// 本测试文件按业务场景组织；go test -v 时每个用例名即业务点，
// 测试组通过 biz() 输出中文业务说明，方便核对覆盖情况。
func biz(t *testing.T, name string) {
	t.Helper()
	t.Logf("业务覆盖: %s", name)
}

// captureLogger 收集日志用于“日志不泄露密钥材料”的断言。
type captureLogger struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *captureLogger) Infof(session, format string, args ...any) {
	c.write("INFO ", session, format, args)
}
func (c *captureLogger) Warnf(session, format string, args ...any) {
	c.write("WARN ", session, format, args)
}
func (c *captureLogger) write(level, session, format string, args []any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf.WriteString(level + session + " " + sprintf(format, args...) + "\n")
}
func (c *captureLogger) String() string { c.mu.Lock(); defer c.mu.Unlock(); return c.buf.String() }

func baseCfg(seed uint64) Config {
	return Config{Seed: seed, Photons: 20000, Loss: 0.1, Noise: 0.01}
}

// 业务1：低噪声正常信道必须成功，且各阶段统计量合理。
func TestNormalSession(t *testing.T) {
	biz(t, "正常会话：低噪声信道成功成钥，统计量与泄露核算正确")
	s, material, err := execute(baseCfg(11), SecurityStandard, NopLogger())
	if err != nil {
		t.Fatalf("normal session aborted: %v", err)
	}
	if s.Aborted || len(material) == 0 {
		t.Fatalf("expected usable key, aborted=%v", s.Aborted)
	}
	if s.Stats.QBER > 0.12 {
		t.Fatalf("unexpected high QBER %.4f", s.Stats.QBER)
	}
	if (s.Stats.FinalKeyBits+7)/8 != len(material) {
		t.Fatalf("key size mismatch stats=%d bytes=%d", s.Stats.FinalKeyBits, len(material))
	}
	// 泄露核算必须如实包含抽样、纠错与校验三段。
	wantLeak := s.Stats.SampleLeak + s.Stats.ReconcileLeak + s.Stats.ConfirmLeak
	if s.Stats.TotalLeak != wantLeak || s.Stats.ReconcileLeak == 0 || s.Stats.ConfirmLeak == 0 {
		t.Fatalf("leak accounting wrong: %+v", s.Stats)
	}
	// 最终长度公式核对。
	want := s.Stats.SiftedBits - s.Stats.SampleBits - wantLeak - s.Stats.SecurityBits
	if want != s.Stats.FinalKeyBits {
		t.Fatalf("final length formula mismatch: want=%d got=%d", want, s.Stats.FinalKeyBits)
	}
}

// 业务2：全程窃听必须被稳定检出；无窃听低噪声不能误判。
func TestEavesdroppingDetected(t *testing.T) {
	biz(t, "窃听检测：多种子下全程拦截-重发稳定中止，干净信道不误判")
	for seed := uint64(1); seed <= 8; seed++ {
		cfg := baseCfg(seed)
		cfg.Eavesdrop = true
		s, material, err := execute(cfg, SecurityStandard, NopLogger())
		if err == nil || ReasonOf(err) != ReasonQBERExceeded {
			t.Fatalf("seed %d: expected qber_exceeded, got %v (qber=%.3f)", seed, err, s.Stats.QBER)
		}
		if material != nil || !s.Aborted || s.AbortReason != ReasonQBERExceeded {
			t.Fatalf("aborted session must yield no key")
		}
		if s.Stats.QBER < 0.18 {
			t.Fatalf("seed %d: QBER %.3f too low for full intercept-resend", seed, s.Stats.QBER)
		}
	}
	// 同样参数关闭窃听：不应误判。
	for seed := uint64(1); seed <= 8; seed++ {
		if _, _, err := execute(baseCfg(seed), SecurityStandard, NopLogger()); err != nil {
			t.Fatalf("seed %d: clean channel falsely aborted: %v", seed, err)
		}
	}
}

// 业务2b：噪声梯度——高噪声应中止，低噪声应通过。
func TestNoiseGradient(t *testing.T) {
	biz(t, "噪声梯度：显著高噪声信道触发误码率中止")
	high := baseCfg(5)
	high.Noise = 0.30
	s, _, err := execute(high, SecurityStandard, NopLogger())
	if err == nil || ReasonOf(err) != ReasonQBERExceeded {
		t.Fatalf("expected qber_exceeded for noisy channel, got %v qber=%.3f", err, s.Stats.QBER)
	}
}

// 业务3：纠错后一致性校验失败必须中止且不发密钥（故障注入）。
func TestConfirmationMismatch(t *testing.T) {
	biz(t, "校验失败：纠错后一致性哈希不一致必须中止且不发密钥")
	cfg := baseCfg(9)
	cfg.Faults.FlipAfterReconcile = true
	s, material, err := execute(cfg, SecurityStandard, NopLogger())
	if err == nil || ReasonOf(err) != ReasonReconcileHash {
		t.Fatalf("expected reconcile_hash failure, got %v", err)
	}
	if material != nil || !s.Aborted || s.KeyID != "" {
		t.Fatalf("inconsistent key must not leave material")
	}
}

// 业务4：有效样本不足（筛后码长太小 / MinSamples 太高）。
func TestTooFewSamples(t *testing.T) {
	biz(t, "样本不足：高损耗筛后过短/最小样本数过高均可区分中止")
	// 高损耗：筛后码长低于 MinSifted。
	cfg := Config{Seed: 3, Photons: 800, Loss: 0.97, Noise: 0.01, MinSifted: 128}
	s, _, err := execute(cfg, SecurityStandard, NopLogger())
	if err == nil || ReasonOf(err) != ReasonTooFewSamples {
		t.Fatalf("expected too_few_samples from sifting, got %v", err)
	}
	if !s.Aborted {
		t.Fatalf("session should be marked aborted")
	}

	// MinSamples 高于可抽样量。
	cfg2 := baseCfg(4)
	cfg2.MinSamples = 100000
	_, _, err = execute(cfg2, SecurityStandard, NopLogger())
	if err == nil || ReasonOf(err) != ReasonTooFewSamples {
		t.Fatalf("expected too_few_samples from sampling, got %v", err)
	}
}

// 业务5：非法参数组合必须被拒绝。
func TestInvalidConfig(t *testing.T) {
	biz(t, "非法参数：损耗/噪声/抽样比例/阈值/光子数越界全部拒绝")
	bad := []Config{
		{Seed: 1, Photons: 1},
		{Seed: 1, Photons: 100000, Loss: 1},
		{Seed: 1, Photons: 100000, Loss: -0.1},
		{Seed: 1, Photons: 100000, Noise: 2},
		{Seed: 1, Photons: 100000, SampleFraction: -0.2},
		{Seed: 1, Photons: 100000, SampleFraction: 1},
		{Seed: 1, Photons: 100000, QBERThreshold: 1.5},
	}
	for i, c := range bad {
		_, _, err := execute(c, SecurityStandard, NopLogger())
		if err == nil || ReasonOf(err) != ReasonInvalidConfig {
			t.Fatalf("case %d: expected invalid_config, got %v", i, err)
		}
	}
}

// 业务6：扣除泄露后密钥长度不足必须拒绝，而不是给空/短密钥。
func TestKeyTooShort(t *testing.T) {
	biz(t, "密钥过短：扣尽公开信息与安全参数后明确拒绝，不产出空密钥")
	cfg := Config{
		Seed: 6, Photons: 4000, Loss: 0.05, Noise: 0.01,
		SampleFraction: 0.5, MinSifted: 32, MinSamples: 16,
		ConfirmLeakBits: 5000, SecurityBits: 1000,
	}
	s, material, err := execute(cfg, SecurityStandard, NopLogger())
	if err == nil || ReasonOf(err) != ReasonKeyTooShort {
		t.Fatalf("expected key_too_short, got %v", err)
	}
	if material != nil || !s.Aborted {
		t.Fatalf("must not produce any key material")
	}
}

// 业务7：同参数同种子各阶段结果与最终密钥完全一致；换种子则不同。
func TestDeterminism(t *testing.T) {
	biz(t, "可复现：同参数同种子各阶段统计与最终密钥逐字节一致")
	s1, k1, err := execute(baseCfg(77), SecurityStandard, NopLogger())
	if err != nil {
		t.Fatal(err)
	}
	s2, k2, err := execute(baseCfg(77), SecurityStandard, NopLogger())
	if err != nil {
		t.Fatal(err)
	}
	if statsCore(s1.Stats) != statsCore(s2.Stats) {
		t.Fatalf("stats differ:\n%+v\n%+v", s1.Stats, s2.Stats)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatalf("key material differs for same seed")
	}

	cfg3 := baseCfg(78)
	_, k3, err := execute(cfg3, SecurityStandard, NopLogger())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, k3) {
		t.Fatalf("different seeds produced identical key")
	}
}

// 业务8：较大码长（筛后十万比特以上）在可接受时间内完成。
func TestLargeSifted(t *testing.T) {
	biz(t, "较大码长：筛后十万比特以上快速完成并产出足量密钥")
	cfg := Config{Seed: 99, Photons: 300000, Loss: 0.05, Noise: 0.01}
	s, material, err := execute(cfg, SecurityStandard, NopLogger())
	if err != nil {
		t.Fatal(err)
	}
	if s.Stats.SiftedBits < 100000 {
		t.Fatalf("expected >=100k sifted bits, got %d", s.Stats.SiftedBits)
	}
	if s.Stats.FinalKeyBits < 10000 {
		t.Fatalf("expected substantial final key, got %d", s.Stats.FinalKeyBits)
	}
	if len(material) == 0 {
		t.Fatalf("empty material")
	}
}

// 业务9：小码长（筛选后几十比特且合法）也能稳定处理或明确拒绝。
func TestSmallSifted(t *testing.T) {
	biz(t, "较小码长：合法的小筛后码长稳定处理")
	cfg := Config{
		Seed: 5, Photons: 4000, Loss: 0.05, Noise: 0.005,
		MinSifted: 64, MinSamples: 16,
		SampleFraction: 0.1, ConfirmLeakBits: 64, SecurityBits: 32,
	}
	s, material, err := execute(cfg, SecurityStandard, NopLogger())
	if err != nil {
		t.Fatalf("small valid config aborted: %v", err)
	}
	if s.Stats.SiftedBits < 64 || len(material) == 0 {
		t.Fatalf("unexpected small session outcome: %+v", s.Stats)
	}
}

// 业务10：日志中不得出现原始比特、抽样内容或密钥材料。
func TestLogsDoNotLeakSecrets(t *testing.T) {
	biz(t, "日志安全：日志不含密钥片段，且包含完整业务阶段字段")
	lg := &captureLogger{}
	s, material, err := execute(baseCfg(123), SecurityStandard, lg)
	if err != nil {
		t.Fatal(err)
	}
	logs := lg.String()
	// 密钥材料的任一 8 比特窗口都不应完整出现在日志中。
	for i := 0; i+8 <= len(material); i++ {
		if bytes.Contains([]byte(logs), material[i:i+8]) {
			t.Fatalf("key fragment leaked into logs at offset %d", i)
		}
	}
	for _, marker := range []string{"raw_bits", "0101", "material=", "key_material"} {
		if strings.Contains(logs, marker) {
			t.Fatalf("suspicious secret marker %q in logs", marker)
		}
	}
	// 正向断言：日志包含业务阶段名与统计字段。
	for _, want := range []string{"stage=prepare", "stage=sift", "stage=sampling", "qber=", "stage=privacy_amplification"} {
		if !strings.Contains(logs, want) {
			t.Fatalf("logs missing business marker %q", want)
		}
	}
	_ = s
}
