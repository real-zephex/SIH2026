// Package parser defines the plug-and-play parser contract (REQS.md).
//
// Every source implements: Detect (cheap sniff) + Parse (line -> schema.Event).
// New source = new file + Register() call. See suricata.go for the reference.
package parser

import (
	"crypto/rand"
	"fmt"
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

// Register adds a parser. Call from init() in each source file.
func Register(p Parser) { registry[p.Name()] = p }

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
func DetectAll(line string) string {
	for n, p := range registry {
		if p.Detect(line) {
			return n
		}
	}
	return ""
}

// newUID generates a UUID v4-style trace ID using crypto/rand.
// Canonical helper shared by all parsers (one definition lives here;
// per-file duplicates were removed during the phase-2 merge).
func newUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
