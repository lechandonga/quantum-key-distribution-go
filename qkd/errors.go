package qkd

import "errors"

// Distinguishable failure reasons for sessions and the key pool.
var (
	// Parameter validation.
	ErrInvalidParams = errors.New("qkd: invalid parameter combination")

	// Session abort reasons.
	ErrInsufficientSample      = errors.New("qkd: insufficient effective sample for QBER estimation")
	ErrQBERExceeded            = errors.New("qkd: estimated QBER exceeds security threshold (possible eavesdropping)")
	ErrVerificationFailed      = errors.New("qkd: post error-correction consistency verification failed")
	ErrInsufficientKeyMaterial = errors.New("qkd: sifted key too short to cover leakage and security parameter")

	// Key pool errors.
	ErrKeyNotFound              = errors.New("qkd: key id not found in pool")
	ErrKeyAlreadyConsumed       = errors.New("qkd: key has already been taken")
	ErrInsufficientSecurityRank = errors.New("qkd: requested security level exceeds the key's registered level")
	ErrPoolEmpty                = errors.New("qkd: key pool is exhausted")
)
