package rootproto

import (
	"sync"
	"time"
)

// Pending key TTL: window in which the client must send renewKeyAck after renewKey
const pendingKeyTTL = 30 * time.Second
const keyCleanupInterval = 15 * time.Second

// pendingKey is a new key the client proposed but hasn't ACKed yet
type pendingKey struct {
	peerPublicKey []byte
	session       *Session
	createdAt     time.Time
}

// keyManager tracks per-peer pending keys with a TTL-based cleanup
type keyManager struct {
	mu      sync.Mutex
	pending map[string]*pendingKey
	ticker  *time.Ticker
	stop    chan struct{}
}

func newKeyManager() *keyManager {
	m := &keyManager{
		pending: make(map[string]*pendingKey),
		ticker:  time.NewTicker(keyCleanupInterval),
		stop:    make(chan struct{}),
	}
	go m.cleanupLoop()
	return m
}

func (m *keyManager) close() {
	m.ticker.Stop()
	close(m.stop)
}

func (m *keyManager) cleanupLoop() {
	for {
		select {
		case <-m.ticker.C:
			m.cleanup()
		case <-m.stop:
			return
		}
	}
}

func (m *keyManager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for peerID, p := range m.pending {
		if now.Sub(p.createdAt) > pendingKeyTTL {
			delete(m.pending, peerID)
		}
	}
}

func (m *keyManager) bufferPending(peerID string, peerPublicKey []byte, session *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pending[peerID] = &pendingKey{
		peerPublicKey: peerPublicKey,
		session:       session,
		createdAt:     time.Now(),
	}
}

func (m *keyManager) takePending(peerID string) (*pendingKey, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.pending[peerID]
	if !ok {
		return nil, false
	}
	delete(m.pending, peerID)
	return p, true
}
