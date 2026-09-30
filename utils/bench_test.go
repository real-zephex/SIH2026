package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// benchBatch is the number of lines generated per benchmark op. Large enough to
// amortise loop overhead, small enough to stay in L2-friendly territory.
const benchBatch = 1000

// benchWriteDir is where the Write* benchmarks stream their sample files.
var benchWriteDir string

func TestMain(m *testing.M) {
	d, err := os.MkdirTemp("", "ulpf-synth-bench")
	if err != nil {
		panic(err)
	}
	benchWriteDir = d
	code := m.Run()
	os.RemoveAll(d)
	os.Exit(code)
}

// BenchmarkGenerate measures pure line synthesis (no I/O) per vendor.
func BenchmarkGenerate(b *testing.B) {
	cases := []struct {
		name string
		fn   func(n int, seed int64) []string
	}{
		{"CiscoASA", GenerateCiscoASA},
		{"FortiGate", GenerateFortiGate},
		{"Suricata", GenerateSuricata},
		{"Linux", GenerateLinux},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(benchBatch * 200)) // ~200 B/line nominal
			for i := 0; i < b.N; i++ {
				out := c.fn(benchBatch, int64(i)+1)
				if len(out) != benchBatch {
					b.Fatalf("got %d lines, want %d", len(out), benchBatch)
				}
			}
		})
	}
}

// BenchmarkGenerateParallel measures synthesis scaling across goroutines. The
// generators are pure functions of (n, seed), so this is embarrassingly
// parallel and should scale near-linearly to core count.
//
// Each op does parBatch lines of work per goroutine so the fixed cost of
// spawning goroutines and the completion channel does not dominate the
// measurement.
func BenchmarkGenerateParallel(b *testing.B) {
	const parBatch = 50_000
	for _, procs := range []int{1, 2, 4, 8, 12} {
		b.Run(procsName(procs), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				done := make(chan struct{}, procs)
				for w := 0; w < procs; w++ {
					go func(w int) {
						_ = GenerateCiscoASA(parBatch, int64(w*7919+i)+1)
						_ = GenerateFortiGate(parBatch, int64(w*104729+i)+1)
						_ = GenerateSuricata(parBatch, int64(w*15485863+i)+1)
						_ = GenerateLinux(parBatch, int64(w*32452843+i)+1)
						done <- struct{}{}
					}(w)
				}
				for w := 0; w < procs; w++ {
					<-done
				}
			}
			b.ReportMetric(float64(b.N*procs*parBatch*4), "lines/op")
		})
	}
}

// BenchmarkWriteSampleFile measures end-to-end synthesis-to-disk, which is how
// sample corpora and load files are actually produced.
func BenchmarkWriteSampleFile(b *testing.B) {
	cases := []struct {
		name string
		fn   func(path string, n int, seed int64) error
	}{
		{"CiscoASA", WriteCiscoASASamples},
		{"FortiGate", WriteFortiGateSamples},
		{"Suricata", WriteSuricataSamples},
		{"Linux", WriteLinuxSamples},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			path := filepath.Join(benchWriteDir, c.name+".log")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := c.fn(path, 20000, int64(i)+1); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			fi, _ := os.Stat(path)
			if fi != nil {
				b.ReportMetric(float64(fi.Size())/float64(b.N), "bytes/op")
			}
			os.Remove(path)
		})
	}
}

func procsName(n int) string {
	if n == 1 {
		return "1proc"
	}
	return strings.TrimSpace(itoa(n) + "proc")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
