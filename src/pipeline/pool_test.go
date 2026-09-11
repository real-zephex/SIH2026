package pipeline

import (
	"context"
	"runtime"
	"testing"
	"time"

	"sih/utils"
)

func TestTickerFeedContinuous(t *testing.T) {
	feed := TickerFeed{
		Source:   "test",
		Interval: 100 * time.Millisecond,
		Batch:    10,
		Gen: func(n int) []string {
			out := make([]string, n)
			for i := range out {
				out[i] = `{"timestamp":"2018-03-24T14:37:19.037299-0600","event_type":"flow","src_ip":"10.0.0.1","src_port":1,"dest_ip":"10.0.0.2","dest_port":80,"proto":"TCP"}`
			}
			return out
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := NewPool(2, t.TempDir())
	in := FanIn(ctx, feed)
	go pool.Run(ctx, in)
	// Two ticks must deliver 2 batches through the full parse path.
	deadline := time.Now().Add(5 * time.Second)
	for pool.Stats.Parsed.Load() < 20 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if got := pool.Stats.Parsed.Load(); got < 20 {
		t.Fatalf("parsed=%d, want >= 20 (continuous feed stalled)", got)
	}
}

func TestPoolSoakAllSources(t *testing.T) {
	feeds := []Feed{
		SynthFeed{Source: "cisco_asa", Lines_: utils.GenerateCiscoASA(500, 7)},
		SynthFeed{Source: "fortigate", Lines_: utils.GenerateFortiGate(500, 7)},
		SynthFeed{Source: "suricata", Lines_: utils.GenerateSuricata(500, 7)},
		SynthFeed{Source: "linux", Lines_: utils.GenerateLinux(500, 7)},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := NewPool(runtime.NumCPU(), t.TempDir())
	in := FanIn(ctx, feeds...)
	done := make(chan struct{})
	go func() { pool.Run(ctx, in); close(done) }()
	n := 0
	for range pool.Out {
		n++
	}
	<-done
	if n != 2000 {
		t.Fatalf("parsed %d events, want 2000", n)
	}
	snap := pool.Stats.Snapshot(len(pool.Out))
	t.Logf("stats: %v", snap)
	if snap["failed"].(int64) != 0 {
		t.Fatalf("failures: %v", snap)
	}
	if snap["spilled"].(int64) != 0 {
		t.Fatalf("spills: %v", snap)
	}
}

func TestPoolFileTailSamples(t *testing.T) {
	feeds := []Feed{
		FileTail{Source: "cisco", Path: "../../samples/cisco_asa.log"},
		FileTail{Source: "fortigate", Path: "../../samples/fortigate.log"},
		FileTail{Source: "suricata", Path: "../../samples/suricata_eve.json"},
		FileTail{Source: "linux", Path: "../../samples/linux_iptables.log"},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := NewPool(4, t.TempDir())
	in := FanIn(ctx, feeds...)
	go pool.Run(ctx, in)
	n := 0
	for range pool.Out {
		n++
	}
	// 20 + 20 + 30 + 18 detectable (linux audit+sudo undetectable by design).
	if n != 88 {
		t.Fatalf("parsed %d events, want 88", n)
	}
}
