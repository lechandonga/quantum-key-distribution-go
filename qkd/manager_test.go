package qkd

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

// 业务：密钥唯一标识、一次性取用、重复/未知/等级不足/池耗尽均可区分拒绝。
func TestKeyPoolAcquisition(t *testing.T) {
	biz(t, "密钥池：唯一标识/一次性/重复取用/未知标识/等级不足/池耗尽拒绝")
	mgr := NewManager(NopLogger())
	s, err := mgr.Run(baseCfg(21), SecurityStandard)
	if err != nil {
		t.Fatal(err)
	}
	id := s.KeyID
	if id == "" {
		t.Fatalf("missing key id")
	}

	k1, err := mgr.Acquire(id, SecurityStandard)
	if err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}
	if k1.ID != id || len(k1.Material) == 0 {
		t.Fatalf("acquired key malformed")
	}

	if _, err := mgr.Acquire(id, SecurityStandard); ReasonOf(err) != ReasonKeyConsumed {
		t.Fatalf("expected key_consumed, got %v", err)
	}
	if _, err := mgr.Acquire("key-unknown", SecurityStandard); ReasonOf(err) != ReasonKeyUnknown {
		t.Fatalf("expected key_unknown, got %v", err)
	}

	// 登记为 Standard 的密钥不能按 Enhanced 领取。
	s2, err := mgr.Run(baseCfg(22), SecurityStandard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Acquire(s2.KeyID, SecurityEnhanced); ReasonOf(err) != ReasonSecurityLevel {
		t.Fatalf("expected security_level_too_high, got %v", err)
	}
	// 被安全等级拒绝后密钥仍可按原等级领取。
	if _, err := mgr.Acquire(s2.KeyID, SecurityStandard); err != nil {
		t.Fatalf("level check must not consume key: %v", err)
	}

	if _, err := mgr.AcquireAny(SecurityEnhanced); ReasonOf(err) != ReasonPoolExhausted {
		t.Fatalf("expected pool_exhausted, got %v", err)
	}
}

// 业务：中止会话不得留下任何可被取用的密钥。
func TestAbortedSessionLeavesNoKey(t *testing.T) {
	biz(t, "安全隔离：中止会话不在密钥池留下任何可领取密钥")
	mgr := NewManager(NopLogger())
	cfg := baseCfg(31)
	cfg.Eavesdrop = true
	s, err := mgr.Run(cfg, SecurityStandard)
	if ReasonOf(err) != ReasonQBERExceeded {
		t.Fatalf("expected abort, got %v", err)
	}
	if s.KeyID != "" {
		t.Fatalf("aborted session must not have key id")
	}
	if mgr.AvailableKeys(SecurityStandard) != 0 {
		t.Fatalf("pool must be empty")
	}
	if _, err := mgr.AcquireAny(SecurityStandard); ReasonOf(err) != ReasonPoolExhausted {
		t.Fatalf("expected pool_exhausted, got %v", err)
	}
}

// 业务：多会话并发执行互不干扰。
func TestConcurrentSessions(t *testing.T) {
	biz(t, "并发会话：多个会话并行执行互不干扰、密钥各不相同（-race 验证）")
	mgr := NewManager(NopLogger())
	const n = 12
	var wg sync.WaitGroup
	errs := make([]error, n)
	keys := make([][]byte, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			cfg := baseCfg(uint64(1000 + i))
			s, err := mgr.Run(cfg, SecurityStandard)
			if err != nil {
				errs[i] = err
				return
			}
			k, err := mgr.Acquire(s.KeyID, SecurityStandard)
			if err != nil {
				errs[i] = err
				return
			}
			keys[i] = k.Material
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d failed: %v", i, err)
		}
	}
	if mgr.AvailableKeys(SecurityStandard) != 0 {
		t.Fatalf("all keys should have been consumed")
	}
	// 各会话密钥应两两不同。
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if bytes.Equal(keys[i], keys[j]) {
				t.Fatalf("workers %d,%d got identical keys", i, j)
			}
		}
	}
}

// 业务：并发抢同一把密钥，只有一个调用方能拿到（竞态检测下验证）。
func TestConcurrentSingleKeyContest(t *testing.T) {
	biz(t, "并发取用：同一密钥高并发争抢时恰有一个调用方成功（-race 验证）")
	for trial := 0; trial < 10; trial++ {
		mgr := NewManager(NopLogger())
		s, err := mgr.Run(baseCfg(uint64(500+trial)), SecurityStandard)
		if err != nil {
			t.Fatal(err)
		}
		const contenders = 16
		var wg sync.WaitGroup
		var mu sync.Mutex
		winners, consumed, other := 0, 0, 0
		wg.Add(contenders)
		for i := 0; i < contenders; i++ {
			go func() {
				defer wg.Done()
				_, err := mgr.Acquire(s.KeyID, SecurityStandard)
				mu.Lock()
				defer mu.Unlock()
				switch ReasonOf(err) {
				case "":
					winners++
				case ReasonKeyConsumed:
					consumed++
				default:
					other++
				}
			}()
		}
		wg.Wait()
		if winners != 1 || consumed != contenders-1 || other != 0 {
			t.Fatalf("trial %d: winners=%d consumed=%d other=%d", trial, winners, consumed, other)
		}
	}
}

// 业务：通过管理器重复运行同参数同种子，最终密钥一致，实例各自独立。
func TestManagerReproducibility(t *testing.T) {
	biz(t, "管理器可复现：同参数同种子重复运行密钥一致、会话实例独立")
	mgr := NewManager(NopLogger())
	s1, err := mgr.Run(baseCfg(888), SecurityStandard)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := mgr.Run(baseCfg(888), SecurityStandard)
	if err != nil {
		t.Fatal(err)
	}
	if s1.ID == s2.ID {
		t.Fatalf("repeated runs need distinct session instances, both=%s", s1.ID)
	}
	if statsCore(s1.Stats) != statsCore(s2.Stats) {
		t.Fatalf("stats must reproduce")
	}
	k1, _ := mgr.Acquire(s1.KeyID, SecurityStandard)
	k2, _ := mgr.Acquire(s2.KeyID, SecurityStandard)
	if !bytes.Equal(k1.Material, k2.Material) {
		t.Fatalf("same seed must produce same key material")
	}
}

func TestAcquireAnyDistinctKeys(t *testing.T) {
	biz(t, "批量取用：AcquireAny 逐把发放不重复，取尽后池耗尽")
	mgr := NewManager(NopLogger())
	for i := 0; i < 3; i++ {
		if _, err := mgr.Run(baseCfg(uint64(700+i)), SecurityStandard); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		k, err := mgr.AcquireAny(SecurityStandard)
		if err != nil {
			t.Fatal(err)
		}
		if seen[k.ID] {
			t.Fatalf("key %s handed out twice", k.ID)
		}
		seen[k.ID] = true
	}
	if _, err := mgr.AcquireAny(SecurityStandard); ReasonOf(err) != ReasonPoolExhausted {
		t.Fatal(fmt.Sprintf("want exhausted got %v", err))
	}
}
