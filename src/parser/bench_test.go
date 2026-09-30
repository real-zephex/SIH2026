package parser

import (
	"flag"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sih/src/schema"
	"sih/utils"
)

// corpusPerVendor is how many lines of each vendor we pre-generate. Lines are
// generated once up-front so generation cost never contaminates parse cost.
const corpusPerVendor = 50_000

// satProfile gates the (slow) worker-scaling profiler so `go test ./...` stays fast.
var satProfile = flag.Bool("satprofile", false,
	"run the worker-scaling saturation profile (workers -> EPS knee)")

// vendorGen pairs a vendor name with its synthetic generator.
var vendorGen = []struct {
	name string
	gen  func(n int, seed int64) []string
}{
	{"cisco_asa", utils.GenerateCiscoASA},
	{"fortigate", utils.GenerateFortiGate},
	{"suricata", utils.GenerateSuricata},
	{"linux", utils.GenerateLinux},
}

// buildCorpus returns per-vendor line slices plus a mixed interleaved corpus,
// which is what a real deployment actually looks like.
func buildCorpus() (map[string][]string, []string) {
	per := make(map[string][]string, len(vendorGen))
	for _, v := range vendorGen {
		per[v.name] = v.gen(corpusPerVendor, 42)
	}
	mixed := make([]string, 0, corpusPerVendor*len(vendorGen))
	// Round-robin interleave so every worker sees a heterogeneous stream.
	for i := 0; i < corpusPerVendor; i++ {
		for _, v := range vendorGen {
			mixed = append(mixed, per[v.name][i])
		}
	}
	return per, mixed
}

var (
	corpusOnce  sync.Once
	perVendor   map[string][]string
	mixedCorpus []string
)

func corpus() (map[string][]string, []string) {
	corpusOnce.Do(func() { perVendor, mixedCorpus = buildCorpus() })
	return perVendor, mixedCorpus
}

// sink accumulates a checksum so the compiler cannot elide parse work.
var sink int64

// BenchmarkDetect measures only the cheap sniff (what DetectAll costs per line).
func BenchmarkDetect(b *testing.B) {
	_, mixed := corpus()
	b.ReportAllocs()
	b.ResetTimer()
	var hits int64
	for i := 0; i < b.N; i++ {
		for _, ln := range mixed {
			if DetectAll(ln) != "" {
				hits++
			}
		}
	}
	atomic.AddInt64(&sink, hits)
	b.ReportMetric(float64(b.N*len(mixed)), "lines")
}

// BenchmarkParse measures vendor Parse only (no Detect, no Validate).
func BenchmarkParse(b *testing.B) {
	per, _ := corpus()
	for _, v := range vendorGen {
		lines := per[v.name]
		p, ok := Get(v.name)
		if !ok {
			b.Fatalf("parser %q not registered", v.name)
		}
		b.Run(v.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			var n int64
			for i := 0; i < b.N; i++ {
				for _, ln := range lines {
					if _, err := p.Parse(ln); err == nil {
						n++
					}
				}
			}
			atomic.AddInt64(&sink, n)
			b.ReportMetric(float64(b.N*len(lines)), "lines")
		})
	}
}

// BenchmarkEndToEnd is the number that matters: DetectAll + Parse + Validate,
// i.e. exactly what one pool worker does per line in the real pipeline.
func BenchmarkEndToEnd(b *testing.B) {
	_, mixed := corpus()
	b.ReportAllocs()
	b.ResetTimer()
	var ok int64
	for i := 0; i < b.N; i++ {
		for _, ln := range mixed {
			name := DetectAll(ln)
			if name == "" {
				continue
			}
			p, _ := Get(name)
			ev, err := p.Parse(ln)
			if err != nil {
				continue
			}
			if err := ev.Validate(); err == nil {
				ok++
			}
		}
	}
	atomic.AddInt64(&sink, ok)
	b.ReportMetric(float64(b.N*len(mixed)), "lines")
	b.ReportMetric(float64(b.N*len(mixed)), "lines/op")
}

// BenchmarkEndToEndParallel reports Go's parallel speedup on the same work.
func BenchmarkEndToEndParallel(b *testing.B) {
	_, mixed := corpus()
	b.ReportAllocs()
	b.SetBytes(int64(len(mixed) * 200))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var local int64
		for pb.Next() {
			for _, ln := range mixed {
				name := DetectAll(ln)
				if name == "" {
					continue
				}
				pp, _ := Get(name)
				ev, err := pp.Parse(ln)
				if err != nil {
					continue
				}
				if err := ev.Validate(); err == nil {
					local++
				}
			}
		}
		atomic.AddInt64(&sink, local)
	})
	b.ReportMetric(float64(b.N*len(mixed)), "lines")
}

// BenchmarkValidate isolates Validate() so the double-hash cost is visible.
func BenchmarkValidate(b *testing.B) {
	_, mixed := corpus()
	// Pre-parse a fixed set of valid events, then only time Validate.
	evs := make([]schema.Event, 0, 4096)
	for _, ln := range mixed {
		name := DetectAll(ln)
		if name == "" {
			continue
		}
		p, _ := Get(name)
		if ev, err := p.Parse(ln); err == nil {
			evs = append(evs, ev)
		}
		if len(evs) == cap(evs) {
			break
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	var n int64
	for i := 0; i < b.N; i++ {
		for j := range evs {
			if err := evs[j].Validate(); err == nil {
				n++
			}
		}
	}
	atomic.AddInt64(&sink, n)
	b.ReportMetric(float64(b.N*len(evs)), "lines")
}

// BenchmarkHashRaw isolates the sha256 cost that Validate() re-pays per event.
func BenchmarkHashRaw(b *testing.B) {
	_, mixed := corpus()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for j := 0; j < len(mixed) && j < 1000; j++ {
			if schema.HashRaw(mixed[j]) != "" {
				n++
			}
		}
	}
	atomic.AddInt64(&sink, int64(n))
}

// TestCostBreakdown attributes per-line cost across pipeline stages using
// single-threaded timing (no worker-pool noise). Run with -v for the table.
func TestCostBreakup(t *testing.T) {
	if !*satProfile {
		t.Skip("set -satprofile to run the cost breakdown")
	}
	per, mixed := corpus()

	fmt.Println("\n=== PER-STAGE COST (single-threaded, ns/line) ===")
	fmt.Printf("%-12s %12s %12s %12s %12s\n", "vendor", "detect", "parse", "validate", "e2e")

	type row struct {
		name                      string
		detect, parse, valid, e2e float64
	}
	var rows []row
	for _, v := range vendorGen {
		lines := per[v.name]
		p, _ := Get(v.name)
		n := float64(len(lines))

		// detect: cost of DetectAll on this vendor's lines
		d0 := time.Now()
		for _, ln := range lines {
			_ = DetectAll(ln)
		}
		detect := float64(time.Since(d0).Nanoseconds()) / n

		// parse
		p0 := time.Now()
		for _, ln := range lines {
			_, _ = p.Parse(ln)
		}
		parse := float64(time.Since(p0).Nanoseconds()) / n

		// validate (events pre-parsed)
		evs := make([]schema.Event, 0, len(lines))
		for _, ln := range lines {
			if ev, err := p.Parse(ln); err == nil {
				evs = append(evs, ev)
			}
		}
		v0 := time.Now()
		for j := range evs {
			_ = evs[j].Validate()
		}
		valid := float64(time.Since(v0).Nanoseconds()) / float64(len(evs))

		// e2e
		e0 := time.Now()
		for _, ln := range lines {
			if nm := DetectAll(ln); nm != "" {
				pp, _ := Get(nm)
				if ev, err := pp.Parse(ln); err == nil {
					_ = ev.Validate()
				}
			}
		}
		e2e := float64(time.Since(e0).Nanoseconds()) / n

		rows = append(rows, row{v.name, detect, parse, valid, e2e})
		fmt.Printf("%-12s %12.0f %12.0f %12.0f %12.0f\n", v.name, detect, parse, valid, e2e)
	}

	// isolate the two suspected hot spots
	h0 := time.Now()
	for i := 0; i < 1000; i++ {
		_ = schema.HashRaw(mixed[i])
	}
	hash := float64(time.Since(h0).Nanoseconds()) / 1000

	u0 := time.Now()
	for i := 0; i < 1000; i++ {
		_ = newUID()
	}
	uid := float64(time.Since(u0).Nanoseconds()) / 1000

	fmt.Printf("\nsha256(raw)      : %8.0f ns/op\n", hash)
	fmt.Printf("newUID()         : %8.0f ns/op  (crypto/rand syscall + Sprintf)\n", uid)
	fmt.Printf("mixed corpus     : %d lines\n", len(mixed))

	total := 0.0
	for _, r := range rows {
		total += r.e2e
	}
	fmt.Printf("mean e2e         : %8.0f ns/line -> %.0f lines/sec/core\n",
		total/float64(len(rows)), 1e9/(total/float64(len(rows))))
}

// TestSaturationProfile finds the upper processing limit: it sweeps worker
// counts and reports EPS for two distribution models.
//
//	mode A (index): atomic work-stealing — measures the pure CPU ceiling.
//	mode B (chan):  buffered channel (10k, like the real pipeline) — measures
//	                the realistic ceiling including channel + contention cost.
func TestSaturationProfile(t *testing.T) {
	if !*satProfile {
		t.Skip("set -satprofile to run the saturation profile")
	}
	_, mixed := corpus()
	total := len(mixed)
	fmt.Printf("\n=== SATURATION PROFILE ===\n")
	fmt.Printf("GOMAXPROCS=%d  NumCPU=%d  corpus=%d lines\n\n",
		runtime.GOMAXPROCS(0), runtime.NumCPU(), total)

	workers := []int{1, 2, 4, 6, 8, 10, 12, 16, 24, 32, 48}
	reps := 5

	type result struct {
		workers int
		mode    string
		eps     float64
		ok      int64
	}
	var results []result

	run := func(w int, mode string) (float64, int64) {
		best, okCount := 0.0, int64(0)
		for rep := 0; rep < reps; rep++ {
			var ok int64
			var idx int64
			start := time.Now()

			process := func(ln string) {
				nm := DetectAll(ln)
				if nm == "" {
					return
				}
				p, _ := Get(nm)
				ev, err := p.Parse(ln)
				if err != nil {
					return
				}
				if ev.Validate() == nil {
					atomic.AddInt64(&ok, 1)
				}
			}

			var wg sync.WaitGroup
			switch mode {
			case "index":
				for k := 0; k < w; k++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for {
							i := atomic.AddInt64(&idx, 1) - 1
							if i >= int64(total) {
								return
							}
							process(mixed[i])
						}
					}()
				}
			case "chan":
				ch := make(chan string, 10000)
				var feeder sync.WaitGroup
				feeder.Add(1)
				go func() {
					defer feeder.Done()
					for _, ln := range mixed {
						ch <- ln
					}
					close(ch)
				}()
				for k := 0; k < w; k++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for ln := range ch {
							process(ln)
						}
					}()
				}
				feeder.Wait()
			}
			wg.Wait()

			el := time.Since(start).Seconds()
			eps := float64(total) / el
			if eps > best {
				best, okCount = eps, ok
			}
		}
		return best, okCount
	}

	for _, mode := range []string{"index", "chan"} {
		fmt.Printf("--- mode=%s ---\n", mode)
		fmt.Printf("%8s %14s %12s %10s\n", "workers", "EPS", "vs 1 core", "parsed")
		base := 0.0
		for _, w := range workers {
			eps, ok := run(w, mode)
			if w == 1 {
				base = eps
			}
			results = append(results, result{w, mode, eps, ok})
			fmt.Printf("%8d %14.0f %11.2fx %10d\n", w, eps, eps/base, ok)
		}
		fmt.Println()
	}

	// Report the knee: last worker count that still gained >5% throughput.
	for _, mode := range []string{"index", "chan"} {
		var knee result
		for i, r := range results {
			if r.mode != mode {
				continue
			}
			if i == 0 {
				knee = r
				continue
			}
			prev := results[i-1]
			if prev.mode != mode {
				continue
			}
			if r.eps > prev.eps*1.05 {
				knee = r
			}
		}
		peak := 0.0
		for _, r := range results {
			if r.mode == mode && r.eps > peak {
				peak = r.eps
			}
		}
		fmt.Printf("mode=%-6s knee at %2d workers (%.0f EPS), peak %.0f EPS (%.1f%% of knee)\n\n",
			mode, knee.workers, knee.eps, peak, 100*peak/knee.eps)
	}

	// sorted dump for the report
	sort.Slice(results, func(i, j int) bool {
		if results[i].mode != results[j].mode {
			return results[i].mode < results[j].mode
		}
		return results[i].workers < results[j].workers
	})
	fmt.Println("workers,mode,eps")
	for _, r := range results {
		fmt.Printf("%d,%s,%.0f\n", r.workers, r.mode, r.eps)
	}
}
