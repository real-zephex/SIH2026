// Package parser defines the plug-and-play parser contract (REQS.md).
//
// Every source implements: Detect (cheap sniff) + Parse (line -> schema.Event).
// New source = new file + Register() call. See suricata.go for the reference.
package parser

import (
	"crypto/rand"
	"encoding/binary"
	"sync/atomic"
	"time"

	"sih/src/schema"
)

// Parser is a single log-source parser.
type Parser interface {
	Name() string
	Detect(line string) bool
	Parse(line string) (schema.Event, error)
}

var registry = map[string]Parser{}

// order preserves registration order. DetectAll walks this slice rather than
// ranging over the map, which makes detection deterministic when a line could
// satisfy more than one parser (map iteration order is randomised in Go) and
// avoids per-call map-iterator setup on the hottest path in the pipeline.
var order []Parser

// Register adds a parser. Call from init() in each source file.
func Register(p Parser) {
	if _, dup := registry[p.Name()]; !dup {
		order = append(order, p)
	}
	registry[p.Name()] = p
}

// Get returns a registered parser by name.
func Get(name string) (Parser, bool) { p, ok := registry[name]; return p, ok }

// Names lists registered parsers (for /stats, dashboard).
func Names() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	return out
}

// DetectAll returns the first parser whose Detect matches, or "".
// Walks parsers in registration order so the result is deterministic.
func DetectAll(line string) string {
	for _, p := range order {
		if p.Detect(line) {
			return p.Name()
		}
	}
	return ""
}

// newUID generates a UUID v4-style trace ID.
//
// The original implementation called crypto/rand.Read (a getrandom syscall)
// and then fmt.Sprintf on five byte slices, costing ~449 ns and several
// allocations for every single parsed event. Unpredictability is not a
// requirement for a log correlation id, so this uses a process-random 64-bit
// prefix drawn once at init plus a strictly increasing atomic counter.
//
// Uniqueness: lo = prefixLo + c*0x9E3779B97F4A7C15 is injective in c (the
// multiplier is odd, so it is a bijection mod 2^64 and addition preserves it),
// so no two events in a process can share a UID. Collision risk across
// processes is 2^-64 per pair, and the v4 version/variant bits are preserved
// so the output is still a well-formed RFC 4122 UUID.
var (
	uidPrefixHi, uidPrefixLo = randomPrefix()
	uidCounter               atomic.Uint64
)

func randomPrefix() (hi, lo uint64) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fall back to time; uniqueness still holds via the counter.
		n := uint64(time.Now().UnixNano())
		return n, n ^ 0x9E3779B97F4A7C15
	}
	return binary.BigEndian.Uint64(b[0:8]), binary.BigEndian.Uint64(b[8:16])
}

// hexUID renders the 16 bytes as 8-4-4-4-12 lowercase hex with one allocation.
func hexUID(b []byte) string {
	const hexd = "0123456789abcdef"
	var out [36]byte
	n := 0
	put := func(v byte) {
		out[n] = hexd[v>>4]
		out[n+1] = hexd[v&0x0f]
		n += 2
	}
	dash := func() {
		out[n] = '-'
		n++
	}
	for i := 0; i < 4; i++ {
		put(b[i])
	}
	dash()
	for i := 4; i < 6; i++ {
		put(b[i])
	}
	dash()
	for i := 6; i < 8; i++ {
		put(b[i])
	}
	dash()
	for i := 8; i < 10; i++ {
		put(b[i])
	}
	dash()
	for i := 10; i < 16; i++ {
		put(b[i])
	}
	return string(out[:n])
}

func newUID() string {
	c := uidCounter.Add(1)
	lo := uidPrefixLo + c*0x9E3779B97F4A7C15
	hi := uidPrefixHi ^ (c * 0xD6E8FEB86659FD93)

	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], lo)
	binary.BigEndian.PutUint64(b[8:16], hi)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return hexUID(b[:])
}
