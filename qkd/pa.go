package qkd

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
)

// binaryEntropy is h2(p) = -p log2 p - (1-p) log2(1-p).
func binaryEntropy(p float64) float64 {
	if p <= 0 || p >= 1 {
		return 0
	}
	return -p*math.Log2(p) - (1-p)*math.Log2(1-p)
}

// privacyAmplify derives the final key length from the sifted length, the
// estimated QBER, all public leakage (error correction + verification) and
// the security parameter, then extracts the key with a SHA-256 based
// universal hash (seeded, counter mode). It refuses to produce a short or
// empty key when the entropy budget is insufficient.
func (s *session) privacyAmplify(aKey []byte, qber float64) ([]byte, error) {
	n := len(aKey)
	leak := s.stats.LeakEC + s.stats.LeakVerify
	budget := int(math.Floor(float64(n)*(1-binaryEntropy(qber)))) - leak - s.params.SecurityParam
	s.log.stage("pa sifted=%d qber=%.4f leak_ec=%d leak_verify=%d sec=%d budget=%d",
		n, qber, s.stats.LeakEC, s.stats.LeakVerify, s.params.SecurityParam, budget)
	if budget <= 0 {
		s.log.stage("abort reason=insufficient_key_material budget=%d", budget)
		return nil, fmt.Errorf("%w: sifted=%d leak=%d sec=%d budget=%d",
			ErrInsufficientKeyMaterial, n, leak, s.params.SecurityParam, budget)
	}
	// Round down to whole bytes so the stored key length matches exactly.
	budget -= budget % 8
	if budget <= 0 {
		s.log.stage("abort reason=insufficient_key_material budget=%d", budget)
		return nil, fmt.Errorf("%w: sifted=%d leak=%d sec=%d budget=%d",
			ErrInsufficientKeyMaterial, n, leak, s.params.SecurityParam, budget)
	}
	// Public extractor seed derived from the session RNG.
	var seed [8]byte
	binary.BigEndian.PutUint64(seed[:], uint64(s.rng.Int63()))
	key := extractKey(aKey, seed[:], budget)
	s.stats.FinalBits = budget
	return key, nil
}

// extractKey hashes the reconciled key with a public seed in counter mode and
// returns outBits bits, MSB-first packed.
func extractKey(key []byte, seed []byte, outBits int) []byte {
	packed := packBits(key)
	out := make([]byte, (outBits+7)/8)
	var ctr [8]byte
	pos := 0
	for pos < len(out) {
		h := sha256.New()
		h.Write(seed)
		h.Write(ctr[:])
		h.Write(packed)
		digest := h.Sum(nil)
		pos += copy(out[pos:], digest)
		binary.BigEndian.PutUint64(ctr[:], binary.BigEndian.Uint64(ctr[:])+1)
	}
	// Zero the padding bits of the last byte.
	if rem := outBits % 8; rem != 0 {
		out[len(out)-1] &= 0xFF << (8 - rem)
	}
	return out
}

// popcount is kept for tests and diagnostics.
func popcount(b []byte) int {
	c := 0
	for _, x := range b {
		c += bits.OnesCount8(x)
	}
	return c
}
