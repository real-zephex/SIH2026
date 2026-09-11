package output

import (
	"sync"

	"sih/src/schema"
)

// SSEBuf is the per-subscriber buffer. Slow clients are dropped, never
// allowed to stall the dbWriter broadcast (DB path never waits on SSE).
const SSEBuf = 100

// Hub fans committed events out to live SSE subscribers.
// It holds no history: subscribers receive events published after Subscribe
// (history always comes from Store via /api/events).
type Hub struct {
	mu   sync.Mutex
	subs map[chan schema.Event]struct{}
	// Dropped counts slow-subscriber drops for /stats.
	Dropped int64
	bufSize int
}

// NewHub builds a Hub (bufSize <= 0 defaults to SSEBuf).
func NewHub(bufSize int) *Hub {
	if bufSize <= 0 {
		bufSize = SSEBuf
	}
	h := &Hub{subs: map[chan schema.Event]struct{}{}}
	h.bufSize = bufSize
	return h
}

// Publish broadcasts a committed batch. Non-blocking per subscriber.
func (h *Hub) Publish(batch []schema.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		for _, ev := range batch {
			select {
			case ch <- ev:
			default:
				h.Dropped++
			}
		}
	}
}

// Subscribe registers a live consumer. Unsubscribe closes the channel.
func (h *Hub) Subscribe() <-chan schema.Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch := make(chan schema.Event, h.bufSize)
	h.subs[ch] = struct{}{}
	return ch
}

// Unsubscribe removes a consumer and closes its channel.
func (h *Hub) Unsubscribe(ch <-chan schema.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.subs {
		if (<-chan schema.Event)(c) == ch {
			delete(h.subs, c)
			close(c)
			return
		}
	}
}

// Subscribers returns the live subscriber count (for /stats).
func (h *Hub) Subscribers() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}
