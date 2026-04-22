package rootproto

import "sync"

const replayCacheSize = 5000

// replayCache tracks recently-seen requestIds (which are uuids) with FIFO eviction at capacity
type replayCache struct {
	mu    sync.Mutex
	seen  map[string]struct{}
	order []string // ring buffer of insertion order for eviction
	next  int      // next write position in order
}

func newReplayCache() *replayCache {
	return &replayCache{
		seen:  make(map[string]struct{}, replayCacheSize),
		order: make([]string, replayCacheSize),
	}
}

// check returns true if the requestId was already seen; otherwise records it
func (c *replayCache) check(requestID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.seen[requestID]; ok {
		return true
	}
	if evicted := c.order[c.next]; evicted != "" {
		delete(c.seen, evicted)
	}
	c.order[c.next] = requestID
	c.next = (c.next + 1) % replayCacheSize
	c.seen[requestID] = struct{}{}
	return false
}