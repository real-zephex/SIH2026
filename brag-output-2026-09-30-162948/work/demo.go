//go:build ignore

// Command demo runs the real ULPF parsers over real sample lines and prints
// the actual canonical OCSF-Slim events, so every field, hash and number shown
// in the walkthrough video is genuine parser output rather than mock data.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sih/src/parser"
	"sih/src/schema"
)

type hero struct {
	Vendor  string
	Source  string
	Raw     string
	Event   schema.Event
	CEF     string
	LEEF    string
	ECSKeys int
}

func show(h hero) {
	js, err := json.MarshalIndent(h.Event, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal:", err)
		return
	}
	fmt.Printf("=== %s ===\n", h.Vendor)
	fmt.Printf("RAW: %s\n", h.Raw)
	fmt.Printf("EVENTID: %s\n", h.Event.EventID())
	fmt.Printf("CLASS: %d/%s  TYPE: %d/%s  ACT: %d/%s  SEV: %d/%s\n",
		h.Event.ClassUID, h.Event.ClassName,
		h.Event.TypeUID, h.Event.TypeName,
		h.Event.ActivityID, h.Event.ActivityName,
		h.Event.SeverityID, h.Event.Severity)
	fmt.Printf("SRC: %s:%d -> DST: %s:%d  PROTO: %s  ACTION: %s  DIR: %s\n",
		h.Event.SrcEndpoint.IP, h.Event.SrcEndpoint.Port,
		h.Event.DstEndpoint.IP, h.Event.DstEndpoint.Port,
		h.Event.ProtocolName, h.Event.Action, h.Event.Direction)
	fmt.Printf("HASH: %s\n", h.Event.RawDataHash)
	fmt.Printf("RAWSIZE: %d\n", h.Event.RawDataSize)
	fmt.Printf("TIMERFC: %s\n", h.Event.TimeRFC3339())
	fmt.Printf("UNMAPPED: %v\n", h.Event.Unmapped)
	fmt.Printf("OBSERVABLES: %v\n", h.Event.Observables)
	fmt.Printf("FINDING: %q CONF: %q\n", h.Event.FindingInfo, h.Event.Confidence)
	fmt.Printf("CEF: %s\n", h.Event.ToCEF())
	fmt.Printf("LEEF: %s\n", h.Event.ToLEEF())
	fmt.Printf("ECSKEYS: %d\n", len(h.Event.ToECS()))
	fmt.Printf("JSON: %s\n\n", js)
}

func firstNonEmpty(path string, pred func(string) bool) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln != "" && pred(ln) {
			return ln, true
		}
	}
	return "", false
}

func main() {
	// The four hero lines used in the video. Each is taken verbatim from the
	// curated captures in samples/ — no hand-editing.
	ufw, _ := firstNonEmpty("samples/linux_iptables.log", func(l string) bool {
		return strings.Contains(l, "[UFW BLOCK]")
	})
	cisco, _ := firstNonEmpty("samples/cisco_asa.log", func(l string) bool {
		return strings.Contains(l, "%ASA-6-302013")
	})
	fgt, _ := firstNonEmpty("samples/fortigate.log", func(l string) bool {
		return strings.Contains(l, `type="traffic"`)
	})
	suri, _ := firstNonEmpty("samples/suricata_eve.json", func(l string) bool {
		return strings.Contains(l, `"event_type": "alert"`)
	})

	heroes := []struct {
		name  string
		raw   string
	}{
		{"Linux", ufw},
		{"Cisco ASA", cisco},
		{"FortiGate", fgt},
		{"Suricata", suri},
	}

	var parsed []hero
	for _, h := range heroes {
		if h.raw == "" {
			fmt.Fprintf(os.Stderr, "WARN: no sample line for %s\n", h.name)
			continue
		}
		name := parser.DetectAll(h.raw)
		if name == "" {
			fmt.Fprintf(os.Stderr, "WARN: DetectAll found nothing for %s\n", h.name)
			continue
		}
		p, ok := parser.Get(name)
		if !ok {
			fmt.Fprintf(os.Stderr, "WARN: no parser %q\n", name)
			continue
		}
		ev, err := p.Parse(h.raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: parse %s: %v\n", name, err)
			continue
		}
		if err := ev.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "WARN: validate %s: %v\n", name, err)
			continue
		}
		parsed = append(parsed, hero{
			Vendor: h.name, Source: name, Raw: h.raw, Event: ev,
			CEF: ev.ToCEF(), LEEF: ev.ToLEEF(), ECSKeys: len(ev.ToECS()),
		})
	}
	for _, h := range parsed {
		show(h)
	}

	// Aggregate detection/validation stats over every curated sample line, so
	// the routing numbers in the video are measured, not asserted.
	type acc struct {
		received, parsed, failed int
		perSrc                   map[string]int
	}
	a := acc{perSrc: map[string]int{}}
	for _, f := range []string{
		"samples/cisco_asa.log", "samples/fortigate.log",
		"samples/suricata_eve.json", "samples/linux_iptables.log",
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		vendor := strings.TrimSuffix(filepath.Base(f), filepath.Ext(f))
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" {
				continue
			}
			a.received++
			name := parser.DetectAll(ln)
			if name == "" {
				a.failed++
				continue
			}
			p, _ := parser.Get(name)
			ev, err := p.Parse(ln)
			if err != nil {
				a.failed++
				continue
			}
			if err := ev.Validate(); err != nil {
				a.failed++
				continue
			}
			a.parsed++
			a.perSrc[fmt.Sprintf("%s<-%s", vendor, name)]++
		}
	}
	fmt.Println("=== AGGREGATE (curated samples) ===")
	fmt.Printf("received=%d parsed=%d failed=%d\n", a.received, a.parsed, a.failed)
	for k, v := range a.perSrc {
		fmt.Printf("  %-40s %d\n", k, v)
	}
}
