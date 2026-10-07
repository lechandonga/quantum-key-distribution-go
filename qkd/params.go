package qkd

import "fmt"

// Params describes one BB84 session. All randomness derives from Seed, so the
// same Params (including Seed) reproduce identical stage statistics and keys.
type Params struct {
	NumQubits     int     // photons Alice prepares
	Seed          int64   // master seed for all (simulated) randomness
	ChannelLoss   float64 // photon loss probability in [0,1)
	ChannelNoise  float64 // bit-flip probability per transmitted photon in [0,0.5)
	Eavesdrop     bool    // Eve performs intercept-resend on every photon
	SampleRatio   float64 // fraction of sifted bits disclosed for QBER estimation, in (0,1)
	MinSample     int     // minimum effective sample size required
	QBERThreshold float64 // abort if estimated QBER exceeds this, in (0,0.5)
	SecurityParam int     // bits of security margin for verification tag and privacy amplification
}

// Validate reports ErrInvalidParams (wrapping a description) when the
// combination is not usable.
func (p Params) Validate() error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidParams, fmt.Sprintf(format, args...))
	}
	if p.NumQubits < 64 {
		return bad("NumQubits must be >= 64, got %d", p.NumQubits)
	}
	if p.ChannelLoss < 0 || p.ChannelLoss >= 1 {
		return bad("ChannelLoss must be in [0,1), got %v", p.ChannelLoss)
	}
	if p.ChannelNoise < 0 || p.ChannelNoise >= 0.5 {
		return bad("ChannelNoise must be in [0,0.5), got %v", p.ChannelNoise)
	}
	if p.SampleRatio <= 0 || p.SampleRatio >= 1 {
		return bad("SampleRatio must be in (0,1), got %v", p.SampleRatio)
	}
	if p.MinSample < 1 {
		return bad("MinSample must be >= 1, got %d", p.MinSample)
	}
	if p.QBERThreshold <= 0 || p.QBERThreshold >= 0.5 {
		return bad("QBERThreshold must be in (0,0.5), got %v", p.QBERThreshold)
	}
	if p.SecurityParam < 16 || p.SecurityParam > 512 {
		return bad("SecurityParam must be in [16,512] bits, got %d", p.SecurityParam)
	}
	return nil
}

// Stats records per-stage, non-secret session counters.
type Stats struct {
	Prepared   int
	Received   int // photons surviving channel loss
	Sifted     int // bits kept after basis reconciliation
	Sampled    int // bits disclosed for QBER estimation
	QBER       float64
	LeakEC     int // bits disclosed during error correction
	LeakVerify int // bits disclosed during consistency verification
	FinalBits  int // final key length after privacy amplification
}
