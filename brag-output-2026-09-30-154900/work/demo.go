//go:build ignore
// Command demo is a one-off generator kept for reproducibility.
// Ignored by the build so it never becomes a package in `go test ./...`;
// run it explicitly:  go run work/demo.go

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"sih/src/parser"
	"sih/src/schema"
)

func main() {
	picks := os.Args[1:]
	for _, p := range picks {
		f, err := os.Open(p)
		if err != nil { fmt.Println("ERR", err); continue }
		sc := bufio.NewScanner(f)
		n := 0
		for sc.Scan() {
			raw := sc.Text()
			if strings.TrimSpace(raw) == "" { continue }
			name := parser.DetectAll(raw)
			if name == "" { continue }
			pr, _ := parser.Get(name)
			ev, err := pr.Parse(raw)
			if err != nil { continue }
			js, _ := json.MarshalIndent(ev, "", "  ")
			fmt.Printf("### SOURCE=%s VENDOR=%s\n%s\n", p, name, js)
			n++
			if n >= 2 { break }
		}
		f.Close()
	}

	// timing: real parse throughput on the real corpus
	start := time.Now()
	total, ok := 0, 0
	for _, p := range picks {
		f, _ := os.Open(p)
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			raw := sc.Text()
			if strings.TrimSpace(raw) == "" { continue }
			total++
			if name := parser.DetectAll(raw); name != "" {
				pr, _ := parser.Get(name)
				if ev, err := pr.Parse(raw); err == nil && ev.Validate() == nil { ok++ }
			}
		}
		f.Close()
	}
	el := time.Since(start)
	fmt.Printf("### THROUGHPUT lines=%d parsed_ok=%d elapsed_ns=%d ns_per_line=%.0f lines_per_sec=%.0f\n",
		total, ok, el.Nanoseconds(), float64(el.Nanoseconds())/float64(total),
		float64(total)/el.Seconds())
	_ = schema.OCSFVersion
}
