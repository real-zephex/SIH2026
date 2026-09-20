package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"sih/src/output"
	"sih/src/pipeline"
	"sih/utils"
)

// ULPF Phase 2: feeds -> parser pool -> chan{10k} -> SQLite batch writer ->
// /api/events + /stream SSE. Tunables are hardcoded consts (see
// src/pipeline/config.go, output.BatchSize/FlushInterval).
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, err := output.OpenSQLite("ulpf.db")
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer store.Close()
	hub := output.NewHub(0)

	pool := pipeline.NewPool(runtime.NumCPU(), "spill")
	feeds := []pipeline.Feed{
		// One-shot curated replays (golden files).
		pipeline.FileTail{Source: "cisco_asa", Path: "samples/cisco_asa.log"},
		pipeline.FileTail{Source: "fortigate", Path: "samples/fortigate.log"},
		pipeline.FileTail{Source: "suricata", Path: "samples/suricata_eve.json"},
		pipeline.FileTail{Source: "linux", Path: "samples/linux_iptables.log"},
	}
	// Continuous background load with per-source rates so the throughput
	// graph shows distinct bands (IDS chattiest, host firewall quietest).
	// Fresh randomness every tick (seed 0). Stand-in for real syslog
	// feeds until those land.
	//
	// Rates: suricata 30/s, cisco 12/s, fortigate ~7/s, linux ~3/s.
	synthRates := []struct {
		source   string
		interval time.Duration
		batch    int
		gen      func(n int, seed int64) []string
	}{
		{"suricata/synth", 1 * time.Second, 30, utils.GenerateSuricata},
		{"cisco_asa/synth", 2 * time.Second, 25, utils.GenerateCiscoASA},
		{"fortigate/synth", 3 * time.Second, 20, utils.GenerateFortiGate},
		{"linux/synth", 4 * time.Second, 10, utils.GenerateLinux},
	}
	for _, sr := range synthRates {
		sr := sr
		feeds = append(feeds, pipeline.TickerFeed{
			Source:   sr.source,
			Interval: sr.interval,
			Batch:    sr.batch,
			Gen: func(n int) []string {
				return sr.gen(n, 0)
			},
		})
	}
	in := pipeline.FanIn(ctx, feeds...)
	poolDone := make(chan struct{})
	go func() { pool.Run(ctx, in); close(poolDone) }()

	writerDone := make(chan int64, 1)
	go func() { writerDone <- output.RunWriter(ctx, pool.Out, store, hub) }()

	srv := output.NewServer(store, hub, pool)
	httpSrv := &http.Server{Addr: "127.0.0.1:8080", Handler: srv}
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("http: %v", err)
		}
	}()
	fmt.Println("ULPF listening on http://127.0.0.1:8080 (/api/events, /stream, /health, /stats)")

	// TickerFeeds run until signal: ingest stays live after the files drain.
	// Feeds close on ctx cancel -> pool closes Out -> writer flushes.
	<-ctx.Done()

	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)

	<-poolDone
	inserted := <-writerDone
	_ = store.Rotate(context.Background())
	n, _ := store.Count(context.Background())
	snap := pool.Stats.Snapshot(0)
	fmt.Fprintf(os.Stdout, "shutdown complete: inserted=%d db_rows=%d stats=%v\n", inserted, n, snap)
}
