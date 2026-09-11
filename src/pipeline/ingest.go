package pipeline

import (
	"bufio"
	"context"
	"os"
	"sync"
	"time"
)

// Line is one raw input line with its source label.
type Line struct {
	Source string // feed name, e.g. "cisco_asa:file"
	Text   string
}

// Feed produces raw lines. FileTail follows files, SynthFeed replays the
// utils generators (load harness + demo seed). A live syslog-TCP feed later
// implements this interface with zero core changes.
type Feed interface {
	// Lines streams lines until ctx is done or the feed is exhausted (then
	// the channel is closed).
	Lines(ctx context.Context) <-chan Line
}

// FileTail follows appended lines of a static file (testdata/samples now,
// live syslog spool later).
type FileTail struct {
	Source string
	Path   string
}

// Lines implements Feed.
func (f FileTail) Lines(ctx context.Context) <-chan Line {
	out := make(chan Line, 256)
	go func() {
		defer close(out)
		fh, err := os.Open(f.Path)
		if err != nil {
			return
		}
		defer fh.Close()
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		var offset int64
		for {
			for sc.Scan() {
				offset++
				select {
				case out <- Line{Source: f.Source, Text: sc.Text()}:
				case <-ctx.Done():
					return
				}
			}
			// Follow appends briefly, then stop (bounded for tests/demos).
			deadline := time.Now().Add(500 * time.Millisecond)
			for time.Now().Before(deadline) {
				select {
				case <-ctx.Done():
					return
				case <-time.After(FilePollInterval):
				}
				st, err := fh.Stat()
				if err != nil || st.Size() <= offset {
					continue
				}
				break
			}
			return
		}
	}()
	return out
}

// SynthFeed replays in-memory lines (utils.GenerateX output).
type SynthFeed struct {
	Source string
	Lines_ []string
}

func (s SynthFeed) Lines(ctx context.Context) <-chan Line {
	out := make(chan Line, 256)
	go func() {
		defer close(out)
		for _, l := range s.Lines_ {
			select {
			case out <- Line{Source: s.Source, Text: l}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// TickerFeed regenerates lines every Interval until ctx ends — the
// continuous background feed (e.g. utils generators with time-based seeds).
// Gen receives the batch size; pipeline stays decoupled from utils.
type TickerFeed struct {
	Source   string
	Interval time.Duration
	Batch    int
	Gen      func(n int) []string
}

// Lines implements Feed.
func (t TickerFeed) Lines(ctx context.Context) <-chan Line {
	out := make(chan Line, 256)
	go func() {
		defer close(out)
		interval := t.Interval
		if interval <= 0 {
			interval = SynthEvery
		}
		batch := t.Batch
		if batch <= 0 {
			batch = SynthBatch
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			for _, l := range t.Gen(batch) {
				select {
				case out <- Line{Source: t.Source, Text: l}:
				case <-ctx.Done():
					return
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return out
}

// FanIn merges feed channels into one (workers share the stream).
func FanIn(ctx context.Context, feeds ...Feed) <-chan Line {
	out := make(chan Line, 256)
	var wg sync.WaitGroup
	wg.Add(len(feeds))
	for _, f := range feeds {
		go func(f Feed) {
			defer wg.Done()
			for ln := range f.Lines(ctx) {
				select {
				case out <- ln:
				case <-ctx.Done():
					return
				}
			}
		}(f)
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}
