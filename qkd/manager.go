package qkd

import (
	"fmt"
	"sync"
)

type keyEntry struct {
	id        string
	material  []byte
	level     SecurityLevel
	consumed  bool
	sessionID string
}

// Manager 集中管理并发执行的会话与一次性密钥池。
// 所有方法均并发安全；同一密钥在并发取用时只会被一个调用方领到。
type Manager struct {
	mu       sync.Mutex
	sessions map[string]*Session
	keys     map[string]*keyEntry
	order    []string // 未消费密钥的登记顺序，支持 AcquireAny
	counter  uint64
	logger   Logger
}

// NewManager 创建管理器；logger 为 nil 时使用空日志器。
func NewManager(logger Logger) *Manager {
	if logger == nil {
		logger = NopLogger()
	}
	return &Manager{
		sessions: make(map[string]*Session),
		keys:     make(map[string]*keyEntry),
		logger:   logger,
	}
}

// Run 执行一次 BB84 会话并登记结果。成功时密钥入池；中止的会话
// （Aborted=true）不产生任何可领取密钥。该方法可被多个 goroutine
// 并发调用，会话之间互不干扰。
func (m *Manager) Run(cfg Config, level SecurityLevel) (*Session, error) {
	// 仿真过程不持锁：各会话使用独立内存结构，可真正并行。
	s, material, err := execute(cfg, level, m.logger)

	m.mu.Lock()
	defer m.mu.Unlock()
	if s == nil {
		return nil, err
	}
	// 相同种子/参数重复运行时会话基址 ID 相同，追加唯一序号以区分实例。
	m.counter++
	if _, exists := m.sessions[s.ID]; exists {
		s.ID = fmt.Sprintf("%s-%d", s.ID, m.counter)
	}
	m.sessions[s.ID] = s
	if !s.Aborted && material != nil {
		m.counter++
		kid := fmt.Sprintf("key-%012x", m.counter)
		m.keys[kid] = &keyEntry{
			id:        kid,
			material:  material,
			level:     level,
			sessionID: s.ID,
		}
		m.order = append(m.order, kid)
		s.KeyID = kid
	}
	return s, err
}

// Key 是领取到的一次性密钥。
type Key struct {
	ID            string
	Material      []byte
	SecurityLevel SecurityLevel
	SessionID     string
}

// Acquire 按标识领取密钥。返回可区分的失败原因：
// ReasonKeyUnknown / ReasonKeyConsumed / ReasonSecurityLevel。
func (m *Manager) Acquire(keyID string, requiredLevel SecurityLevel) (*Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.keys[keyID]
	if !ok {
		return nil, fail(ReasonKeyUnknown, "no key with id %q", keyID)
	}
	if e.consumed {
		return nil, fail(ReasonKeyConsumed, "key %q was already consumed", keyID)
	}
	if requiredLevel > e.level {
		return nil, fail(ReasonSecurityLevel,
			"key %q level %d below required level %d", keyID, e.level, requiredLevel)
	}
	e.consumed = true
	m.removeOrderLocked(keyID)
	m.logger.Infof(e.sessionID, "stage=key_acquire key_id=%s level=%d bytes=%d", e.id, e.level, len(e.material))
	return &Key{ID: e.id, Material: e.material, SecurityLevel: e.level, SessionID: e.sessionID}, nil
}

// AcquireAny 领取池中任意一把满足安全等级的密钥池密钥；没有可用密钥时
// 返回 ReasonPoolExhausted。
func (m *Manager) AcquireAny(requiredLevel SecurityLevel) (*Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, id := range m.order {
		e := m.keys[id]
		if e == nil || e.consumed || requiredLevel > e.level {
			continue
		}
		e.consumed = true
		m.order = append(m.order[:i], m.order[i+1:]...)
		m.logger.Infof(e.sessionID, "stage=key_acquire key_id=%s level=%d bytes=%d", e.id, e.level, len(e.material))
		return &Key{ID: e.id, Material: e.material, SecurityLevel: e.level, SessionID: e.sessionID}, nil
	}
	return nil, fail(ReasonPoolExhausted, "no available key meets level %d", requiredLevel)
}

// Session 返回已登记会话（含中止会话）；未知标识返回错误。
func (m *Manager) Session(sessionID string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sessionID]
	if !ok {
		return nil, fail(ReasonSessionAborted, "no session with id %q", sessionID)
	}
	return s, nil
}

// AvailableKeys 返回满足等级的未消费密钥数量（不暴露密钥内容）。
func (m *Manager) AvailableKeys(level SecurityLevel) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, id := range m.order {
		if e := m.keys[id]; e != nil && !e.consumed && e.level >= level {
			n++
		}
	}
	return n
}

func (m *Manager) removeOrderLocked(id string) {
	for i, x := range m.order {
		if x == id {
			m.order = append(m.order[:i], m.order[i+1:]...)
			return
		}
	}
}
