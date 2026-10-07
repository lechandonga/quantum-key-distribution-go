package qkd

import (
	"context"
	"fmt"
	"log"
	"sync/atomic"
)

// Result describes a completed session. KeyID is empty when the session
// aborted; aborted sessions never leave consumable keys behind.
type Result struct {
	SessionID string
	KeyID     string
	Stats     Stats
}

// Manager runs BB84 sessions concurrently against a shared key pool.
// Each session gets its own seeded RNG, so sessions never interfere and
// identical (Params, Seed) reproduce identical results.
type Manager struct {
	pool   *KeyPool
	logger *log.Logger
	seq    atomic.Uint64
}

func NewManager(pool *KeyPool, logger *log.Logger) *Manager {
	if pool == nil {
		pool = NewKeyPool()
	}
	return &Manager{pool: pool, logger: logger}
}

// Pool exposes the shared key pool.
func (m *Manager) Pool() *KeyPool { return m.pool }

// RunSession executes one full BB84 session. On success the final key is
// stored in the pool and its ID returned; on abort no key is stored.
func (m *Manager) RunSession(ctx context.Context, p Params) (Result, error) {
	id := fmt.Sprintf("s-%d", m.seq.Add(1))
	res := Result{SessionID: id}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	s := newSession(p, &sessionLogger{lg: m.logger, id: id})
	key, stats, err := s.run()
	res.Stats = stats
	if err != nil {
		return res, err
	}
	keyID, err := m.pool.store(key)
	if err != nil {
		return res, err
	}
	res.KeyID = keyID
	return res, nil
}
