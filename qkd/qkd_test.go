package qkd

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"
)

func baseParams() Params {
	return Params{
		NumQubits:     20000,
		Seed:          42,
		ChannelLoss:   0.1,
		ChannelNoise:  0.01,
		SampleRatio:   0.2,
		MinSample:     100,
		QBERThreshold: 0.11,
		SecurityParam: 64,
	}
}

func quietManager() (*Manager, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	logger := log.New(buf, "test ", 0)
	return NewManager(NewKeyPool(), logger), buf
}

func TestNormalSessionProducesConsumableKey(t *testing.T) {
	t.Log("scenario: normal low-noise channel completes all stages")
	mgr, logs := quietManager()
	res, err := mgr.RunSession(context.Background(), baseParams())
	if err != nil {
		t.Fatalf("session aborted: %v", err)
	}
	if res.KeyID == "" {
		t.Fatal("expected a key id")
	}
	t.Logf("stats: %+v", res.Stats)
	if res.Stats.FinalBits <= 0 {
		t.Fatal("expected positive final key length")
	}
	key, err := mgr.Pool().Take(res.KeyID, 0)
	if err != nil {
		t.Fatalf("take: %v", err)
	}
	if len(key)*8 != res.Stats.FinalBits {
		t.Fatalf("key length %d != final bits %d", len(key)*8, res.Stats.FinalBits)
	}
	if !strings.Contains(logs.String(), "done") {
		t.Fatal("expected stage logs")
	}
}

func TestEavesdropAlwaysDetected(t *testing.T) {
	t.Log("scenario: full intercept-resend eavesdropping is reliably detected")
	for seed := int64(1); seed <= 8; seed++ {
		mgr, _ := quietManager()
		p := baseParams()
		p.Seed = seed
		p.Eavesdrop = true
		res, err := mgr.RunSession(context.Background(), p)
		if !errors.Is(err, ErrQBERExceeded) {
			t.Fatalf("seed=%d: expected ErrQBERExceeded, got %v", seed, err)
		}
		if res.KeyID != "" || len(mgr.Pool().List()) != 0 {
			t.Fatalf("seed=%d: aborted session left a consumable key", seed)
		}
	}
}

func TestNoiseLevels(t *testing.T) {
	t.Log("scenario: low noise passes, high noise aborts with QBER error")
	mgr, _ := quietManager()
	p := baseParams()
	p.ChannelNoise = 0.02
	if _, err := mgr.RunSession(context.Background(), p); err != nil {
		t.Fatalf("low-noise session wrongly aborted: %v", err)
	}
	p.ChannelNoise = 0.2
	_, err := mgr.RunSession(context.Background(), p)
	if !errors.Is(err, ErrQBERExceeded) {
		t.Fatalf("expected ErrQBERExceeded for noisy channel, got %v", err)
	}
}

func TestInsufficientSample(t *testing.T) {
	t.Log("scenario: too few sifted bits aborts with insufficient sample")
	mgr, _ := quietManager()
	p := baseParams()
	p.NumQubits = 200
	p.MinSample = 500
	_, err := mgr.RunSession(context.Background(), p)
	if !errors.Is(err, ErrInsufficientSample) {
		t.Fatalf("expected ErrInsufficientSample, got %v", err)
	}
}

func TestInvalidParams(t *testing.T) {
	t.Log("scenario: illegal parameter combinations are rejected")
	cases := []Params{
		func() Params { p := baseParams(); p.NumQubits = 10; return p }(),
		func() Params { p := baseParams(); p.ChannelLoss = 1.5; return p }(),
		func() Params { p := baseParams(); p.ChannelNoise = 0.6; return p }(),
		func() Params { p := baseParams(); p.SampleRatio = 0; return p }(),
		func() Params { p := baseParams(); p.QBERThreshold = 0.9; return p }(),
		func() Params { p := baseParams(); p.SecurityParam = 4; return p }(),
	}
	mgr, _ := quietManager()
	for i, p := range cases {
		if _, err := mgr.RunSession(context.Background(), p); !errors.Is(err, ErrInvalidParams) {
			t.Fatalf("case %d: expected ErrInvalidParams, got %v", i, err)
		}
	}
}

func TestVerificationFailure(t *testing.T) {
	t.Log("scenario: inconsistent keys after EC fail verification and yield no key")
	mgr, _ := quietManager()
	s := newSession(baseParams(), &sessionLogger{})
	a := []byte{0, 1, 1, 0, 1, 1, 0, 0}
	b := []byte{0, 1, 1, 0, 1, 1, 0, 1} // differs in last bit
	if err := s.verify(a, b); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed, got %v", err)
	}
	if len(mgr.Pool().List()) != 0 {
		t.Fatal("no key may be stored on verification failure")
	}
}

func TestInsufficientKeyMaterial(t *testing.T) {
	t.Log("scenario: privacy amplification refuses when leakage exceeds entropy")
	s := newSession(baseParams(), &sessionLogger{})
	s.stats.LeakEC = 100000 // more than any sifted key can cover
	_, err := s.privacyAmplify(make([]byte, 1000), 0.05)
	if !errors.Is(err, ErrInsufficientKeyMaterial) {
		t.Fatalf("expected ErrInsufficientKeyMaterial, got %v", err)
	}
}

func TestDeterministicReproduction(t *testing.T) {
	t.Log("scenario: same params and seed reproduce identical stats and key")
	run := func() (Stats, []byte) {
		mgr, _ := quietManager()
		res, err := mgr.RunSession(context.Background(), baseParams())
		if err != nil {
			t.Fatalf("session: %v", err)
		}
		key, err := mgr.Pool().Take(res.KeyID, 0)
		if err != nil {
			t.Fatalf("take: %v", err)
		}
		return res.Stats, key
	}
	s1, k1 := run()
	s2, k2 := run()
	if s1 != s2 {
		t.Fatalf("stats differ: %+v vs %+v", s1, s2)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("final keys differ for identical params and seed")
	}
}

func TestConcurrentSessionsIndependent(t *testing.T) {
	t.Log("scenario: concurrent sessions do not interfere and keys are unique")
	mgr, _ := quietManager()
	const n = 16
	results := make([]Result, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := baseParams()
			p.Seed = int64(1000 + i)
			results[i], errs[i] = mgr.RunSession(context.Background(), p)
		}(i)
	}
	wg.Wait()
	ids := map[string]bool{}
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("session %d aborted: %v", i, errs[i])
		}
		if ids[results[i].KeyID] {
			t.Fatalf("duplicate key id %s", results[i].KeyID)
		}
		ids[results[i].KeyID] = true
	}
	if got := len(mgr.Pool().List()); got != n {
		t.Fatalf("expected %d keys in pool, got %d", n, got)
	}
}

func TestKeyPoolTakeOnceAndConcurrency(t *testing.T) {
	t.Log("scenario: a key can be taken exactly once, even under concurrency")
	mgr, _ := quietManager()
	res, err := mgr.RunSession(context.Background(), baseParams())
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	const takers = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for i := 0; i < takers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := mgr.Pool().Take(res.KeyID, 0); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("expected exactly 1 successful take, got %d", successes)
	}
	if _, err := mgr.Pool().Take(res.KeyID, 0); !errors.Is(err, ErrKeyAlreadyConsumed) {
		t.Fatalf("expected ErrKeyAlreadyConsumed, got %v", err)
	}
	if _, err := mgr.Pool().Take("deadbeef", 0); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestKeyPoolSecurityLevelAndEmpty(t *testing.T) {
	t.Log("scenario: security-level requirements and pool exhaustion are enforced")
	mgr, _ := quietManager()
	res, err := mgr.RunSession(context.Background(), baseParams())
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	level := res.Stats.FinalBits
	if _, err := mgr.Pool().Take(res.KeyID, level+1); !errors.Is(err, ErrInsufficientSecurityRank) {
		t.Fatalf("expected ErrInsufficientSecurityRank, got %v", err)
	}
	if _, err := mgr.Pool().Take(res.KeyID, level); err != nil {
		t.Fatalf("take at registered level should succeed: %v", err)
	}
	if _, _, err := mgr.Pool().TakeAny(0); !errors.Is(err, ErrPoolEmpty) {
		t.Fatalf("expected ErrPoolEmpty, got %v", err)
	}
}

func TestSiftedLengthScaling(t *testing.T) {
	t.Log("scenario: small and large sifted lengths are handled stably")
	for _, n := range []int{1024, 4096, 200000} {
		mgr, _ := quietManager()
		p := baseParams()
		p.NumQubits = n
		p.MinSample = 32
		res, err := mgr.RunSession(context.Background(), p)
		if err != nil {
			t.Fatalf("n=%d: session aborted: %v", n, err)
		}
		t.Logf("n=%d sifted=%d final=%d", n, res.Stats.Sifted, res.Stats.FinalBits)
	}
}

func TestLogsDoNotLeakKeyMaterial(t *testing.T) {
	t.Log("scenario: logs contain counters only, never key or sample material")
	mgr, logs := quietManager()
	res, err := mgr.RunSession(context.Background(), baseParams())
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	key, err := mgr.Pool().Take(res.KeyID, 0)
	if err != nil {
		t.Fatalf("take: %v", err)
	}
	out := logs.String()
	if strings.Contains(out, hex.EncodeToString(key)) {
		t.Fatal("log contains final key material")
	}
	// Spot-check: no long binary/hex blobs that could encode raw bits.
	for _, field := range strings.Fields(out) {
		if len(field) > 24 && isHexish(field) {
			t.Fatalf("log contains suspicious blob: %q", field)
		}
	}
}

func isHexish(s string) bool {
	for _, c := range s {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}
