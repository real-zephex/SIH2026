package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"sih/src/parser"
	"sih/src/schema"
)

// Stats counts pool flow for /stats and the demo.
type Stats struct {
	Received  atomic.Int64             // raw lines seen
	Parsed    atomic.Int64             // valid events emitted
	Failed    atomic.Int64             // parse/validate failures
	Spilled   atomic.Int64             // full-channel spills to disk
	PerSource map[string]*atomic.Int64 // parsed per parser name
	mu        sync.Mutex
}

func (s *Stats) incSource(name string) {
	s.mu.Lock()
	c, ok := s.PerSource[name]
	if !ok {
		c = &atomic.Int64{}
		s.PerSource[name] = c
	}
	s.mu.Unlock()
	c.Add(1)
}

// Snapshot returns a copy safe for JSON encoding.
func (s *Stats) Snapshot(chanDepth int) map[string]any {
	per := map[string]int64{}
	s.mu.Lock()
	for k, v := range s.PerSource {
		per[k] = v.Load()
	}
	s.mu.Unlock()
	return map[string]any{
		"received":   s.Received.Load(),
		"parsed":     s.Parsed.Load(),
		"failed":     s.Failed.Load(),
		"spilled":    s.Spilled.Load(),
		"per_source": per,
		"chan_depth": chanDepth,
	}
}

// Pool parses lines with NumCPU workers into one buffered channel.
type Pool struct {
	Workers  int
	Out      chan schema.Event // cap ChanCap; sole drainer is output.dbWriter
	Stats    *Stats
	SpillDir string // spill files land here on full channel
}

// NewPool builds a Pool with hardcoded capacity.
func NewPool(workers int, spillDir string) *Pool {
	if workers <= 0 {
		workers = 4
	}
	return &Pool{
		Workers:  workers,
		Out:      make(chan schema.Event, ChanCap),
		Stats:    &Stats{PerSource: map[string]*atomic.Int64{}},
		SpillDir: spillDir,
	}
}

// Run consumes lines until in closes or ctx ends, then closes Out.
func (p *Pool) Run(ctx context.Context, in <-chan Line) {
	var wg sync.WaitGroup
	wg.Add(p.Workers)
	for i := 0; i < p.Workers; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ln, ok := <-in:
					if !ok {
						return
					}
					p.handle(ctx, ln)
				}
			}
		}()
	}
	wg.Wait()
	close(p.Out)
}

func (p *Pool) handle(ctx context.Context, ln Line) {
	p.Stats.Received.Add(1)
	name := parser.DetectAll(ln.Text)
	if name == "" {
		p.Stats.Failed.Add(1)
		return
	}
	pr, ok := parser.Get(name)
	if !ok {
		p.Stats.Failed.Add(1)
		return
	}
	ev, err := pr.Parse(ln.Text)
	if err != nil {
		p.Stats.Failed.Add(1)
		return
	}
	if err := ev.Validate(); err != nil {
		p.Stats.Failed.Add(1)
		return
	}
	select {
	case p.Out <- ev:
		p.Stats.Parsed.Add(1)
		p.Stats.incSource(name)
	case <-ctx.Done():
	case <-time.After(SpillTimeout):
		p.Stats.Spilled.Add(1)
		spill(p.SpillDir, ev)
	}
}

func spill(dir string, ev schema.Event) {
	if dir == "" {
		return
	}
	_ = os.MkdirAll(dir, 0o755)
	fh, err := os.OpenFile(filepath.Join(dir, "spill.jsonl"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer fh.Close()
	raw := ev.RawData + "\n"
	_, _ = fh.WriteString(raw)
}
