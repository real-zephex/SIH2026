// Package parser defines the plug-and-play parser contract (REQS.md).
//
// Every source implements: Detect (cheap sniff) + Parse (line -> schema.Event).
// New source = new file + Register() call. See cisco_asa.go for the reference.
package parser

import "sih/src/schema"

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
