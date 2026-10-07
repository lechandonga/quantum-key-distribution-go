package qkd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// KeyMeta is the public, non-secret descriptor of a stored key.
type KeyMeta struct {
	ID            string
	LengthBits    int
	SecurityLevel int // registered security level in bits (final key length)
	CreatedAt     time.Time
}

type keyRecord struct {
	meta     KeyMeta
	material []byte
	consumed bool
}

// KeyPool stores generated keys centrally. Every key can be taken exactly
// once; Take is atomic under concurrency.
type KeyPool struct {
	mu   sync.Mutex
	keys map[string]*keyRecord
}

func NewKeyPool() *KeyPool {
	return &KeyPool{keys: make(map[string]*keyRecord)}
}

// store adds a key and returns its unique ID.
func (p *KeyPool) store(material []byte) (string, error) {
	var idBytes [16]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return "", fmt.Errorf("qkd: generate key id: %w", err)
	}
	id := hex.EncodeToString(idBytes[:])
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys[id] = &keyRecord{
		meta: KeyMeta{
			ID:            id,
			LengthBits:    len(material) * 8,
			SecurityLevel: len(material) * 8,
			CreatedAt:     time.Now(),
		},
		material: material,
	}
	return id, nil
}

// List returns metadata of keys still available for consumption.
func (p *KeyPool) List() []KeyMeta {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]KeyMeta, 0, len(p.keys))
	for _, r := range p.keys {
		if !r.consumed {
			out = append(out, r.meta)
		}
	}
	return out
}

// Take atomically removes and returns the key material. It fails with
// ErrKeyNotFound for unknown ids, ErrKeyAlreadyConsumed for keys that were
// taken before, and ErrInsufficientSecurityRank when requiredLevel exceeds
// the level registered at generation time.
func (p *KeyPool) Take(id string, requiredLevel int) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.keys[id]
	if !ok {
		return nil, fmt.Errorf("%w: id=%s", ErrKeyNotFound, id)
	}
	if r.consumed {
		return nil, fmt.Errorf("%w: id=%s", ErrKeyAlreadyConsumed, id)
	}
	if requiredLevel > r.meta.SecurityLevel {
		return nil, fmt.Errorf("%w: required=%d registered=%d",
			ErrInsufficientSecurityRank, requiredLevel, r.meta.SecurityLevel)
	}
	r.consumed = true
	material := r.material
	r.material = nil // erase pool copy
	return material, nil
}

// TakeAny atomically takes the oldest available key meeting requiredLevel,
// or fails with ErrPoolEmpty.
func (p *KeyPool) TakeAny(requiredLevel int) (string, []byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var best *keyRecord
	for _, r := range p.keys {
		if r.consumed || r.meta.SecurityLevel < requiredLevel {
			continue
		}
		if best == nil || r.meta.CreatedAt.Before(best.meta.CreatedAt) {
			best = r
		}
	}
	if best == nil {
		return "", nil, fmt.Errorf("%w: required_level=%d", ErrPoolEmpty, requiredLevel)
	}
	best.consumed = true
	material := best.material
	best.material = nil
	return best.meta.ID, material, nil
}
