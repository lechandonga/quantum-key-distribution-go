package qkd

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
)

// session is a single BB84 run between a simulated Alice and Bob.
type session struct {
	params   Params
	rng      *rand.Rand
	log      *sessionLogger
	stats    Stats
	bobBases []byte
}

func newSession(p Params, lg *sessionLogger) *session {
	return &session{
		params: p,
		rng:    rand.New(rand.NewSource(p.Seed)),
		log:    lg,
	}
}

// run executes the full protocol and returns the final key bits packed MSB-first.
func (s *session) run() ([]byte, Stats, error) {
	if err := s.params.Validate(); err != nil {
		return nil, s.stats, err
	}
	aliceBits, aliceBases, bobBits, received := s.prepareAndTransmit()
	aSift, bSift := s.sift(aliceBits, aliceBases, bobBits, received)
	aKey, bKey, qber, err := s.estimateQBER(aSift, bSift)
	if err != nil {
		return nil, s.stats, err
	}
	if err := s.errorCorrect(aKey, bKey, qber); err != nil {
		return nil, s.stats, err
	}
	if err := s.verify(aKey, bKey); err != nil {
		return nil, s.stats, err
	}
	key, err := s.privacyAmplify(aKey, qber)
	if err != nil {
		return nil, s.stats, err
	}
	s.log.stage("done final_bits=%d", s.stats.FinalBits)
	return key, s.stats, nil
}

// prepareAndTransmit simulates photon preparation, the noisy/lossy channel
// and optional intercept-resend eavesdropping.
func (s *session) prepareAndTransmit() (aliceBits, aliceBases, bobBits, received []byte) {
	n := s.params.NumQubits
	aliceBits = randBits(s.rng, n)
	aliceBases = randBits(s.rng, n)
	s.bobBases = randBits(s.rng, n)
	bobBits = make([]byte, n)
	received = make([]byte, n)

	p := s.params
	for i := 0; i < n; i++ {
		if s.rng.Float64() < p.ChannelLoss {
			continue // photon lost
		}
		value := aliceBits[i]
		if p.Eavesdrop {
			// Eve measures in a random basis and resends what she saw.
			if s.rng.Intn(2) != int(aliceBases[i]) {
				value = byte(s.rng.Intn(2)) // collapsed: resent state uncorrelated
			}
		}
		if s.rng.Float64() < p.ChannelNoise {
			value ^= 1
		}
		received[i] = 1
		if s.bobBases[i] == aliceBases[i] {
			bobBits[i] = value
		} else {
			bobBits[i] = byte(s.rng.Intn(2)) // wrong basis: random outcome
		}
	}
	s.stats.Prepared = n
	cnt := 0
	for _, r := range received {
		cnt += int(r)
	}
	s.stats.Received = cnt
	s.log.stage("transmit prepared=%d received=%d", n, cnt)
	return aliceBits, aliceBases, bobBits, received
}

// sift keeps only positions where the photon arrived and bases matched.
func (s *session) sift(aliceBits, aliceBases, bobBits, received []byte) (aSift, bSift []byte) {
	for i := 0; i < len(aliceBits); i++ {
		if received[i] == 1 && aliceBases[i] == s.bobBases[i] {
			aSift = append(aSift, aliceBits[i])
			bSift = append(bSift, bobBits[i])
		}
	}
	s.stats.Sifted = len(aSift)
	s.log.stage("sift kept=%d", len(aSift))
	return aSift, bSift
}

// estimateQBER discloses a random sample of the sifted key and aborts when
// the sample is too small or the error rate exceeds the threshold.
func (s *session) estimateQBER(aSift, bSift []byte) (aKey, bKey []byte, qber float64, err error) {
	n := len(aSift)
	sampleSize := int(float64(n)*s.params.SampleRatio + 0.5)
	if sampleSize < s.params.MinSample {
		s.log.stage("abort reason=insufficient_sample sample=%d min=%d", sampleSize, s.params.MinSample)
		return nil, nil, 0, fmt.Errorf("%w: sample=%d min=%d", ErrInsufficientSample, sampleSize, s.params.MinSample)
	}
	perm := s.rng.Perm(n)
	inSample := make([]bool, n)
	errs := 0
	for _, idx := range perm[:sampleSize] {
		inSample[idx] = true
		if aSift[idx] != bSift[idx] {
			errs++
		}
	}
	qber = float64(errs) / float64(sampleSize)
	s.stats.Sampled = sampleSize
	s.stats.QBER = qber
	s.log.stage("qber sample=%d qber=%.4f threshold=%.4f", sampleSize, qber, s.params.QBERThreshold)
	if qber > s.params.QBERThreshold {
		s.log.stage("abort reason=qber_exceeded")
		return nil, nil, 0, fmt.Errorf("%w: qber=%.4f threshold=%.4f", ErrQBERExceeded, qber, s.params.QBERThreshold)
	}
	// Sampled bits are public: remove them from the key.
	aKey = make([]byte, 0, n-sampleSize)
	bKey = make([]byte, 0, n-sampleSize)
	for i := 0; i < n; i++ {
		if !inSample[i] {
			aKey = append(aKey, aSift[i])
			bKey = append(bKey, bSift[i])
		}
	}
	return aKey, bKey, qber, nil
}

// verify exchanges a truncated hash tag so both sides confirm identical keys.
// The tag bits count as public leakage.
func (s *session) verify(aKey, bKey []byte) error {
	tagBytes := (s.params.SecurityParam + 7) / 8
	nonce := make([]byte, 16)
	binary.BigEndian.PutUint64(nonce, uint64(s.rng.Int63()))
	tag := func(key []byte) []byte {
		h := sha256.New()
		h.Write(nonce)
		h.Write(packBits(key))
		return h.Sum(nil)[:tagBytes]
	}
	at, bt := tag(aKey), tag(bKey)
	s.stats.LeakVerify = tagBytes * 8
	s.log.stage("verify tag_bits=%d", tagBytes*8)
	for i := range at {
		if at[i] != bt[i] {
			s.log.stage("abort reason=verification_failed")
			return fmt.Errorf("%w: keys differ after error correction", ErrVerificationFailed)
		}
	}
	return nil
}

func randBits(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Intn(2))
	}
	return b
}

// packBits packs 0/1 bits into bytes, MSB first.
func packBits(bits []byte) []byte {
	out := make([]byte, (len(bits)+7)/8)
	for i, bit := range bits {
		if bit&1 == 1 {
			out[i>>3] |= 1 << (7 - uint(i&7))
		}
	}
	return out
}
