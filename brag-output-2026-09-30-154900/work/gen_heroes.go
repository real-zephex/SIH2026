//go:build ignore
// Command gen_heroes is a one-off generator kept for reproducibility.
// Ignored by the build so it never becomes a package in `go test ./...`;
// run it explicitly:  go run work/gen_heroes.go

package main

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"

	"sih/src/parser"
)

// hero is one vendor's chosen sample line plus its true normalized output.
type hero struct {
	Vendor  string         `json:"vendor"`
	Raw     string         `json:"raw"`
	ClassUID int           `json:"class_uid"`
	ClassName string       `json:"class_name"`
	TypeUID  int64         `json:"type_uid"`
	TypeName string        `json:"type_name"`
	Severity string        `json:"severity"`
	SeverityID int         `json:"severity_id"`
	Action   string        `json:"action"`
	Activity string        `json:"activity_name"`
	Finding  string        `json:"finding_info"`
	Confidence string      `json:"confidence"`
	SrcIP    string        `json:"src_ip"`
	SrcPort  int           `json:"src_port"`
	DstIP    string        `json:"dst_ip"`
	DstPort  int           `json:"dst_port"`
	Proto    string        `json:"protocol_name"`
	Time     int64         `json:"time"`
	Hash     string        `json:"raw_data_hash"`
	Size     int           `json:"raw_data_size"`
	UID      string        `json:"uid"`
	Unmapped map[string]string `json:"unmapped"`
	Message  string        `json:"message"`
}

func main() {
	// vendor|file|1-based line number
	type pick struct{ vendor, file string; line int }
	picks := []pick{
		{"cisco_asa", "samples/cisco_asa.log", 2},
		{"fortigate", "samples/fortigate.log", 2},
		{"suricata", "samples/suricata_eve.json", 1},
		{"linux", "samples/linux_iptables.log", 2},
	}
	out := make([]hero, 0, len(picks))
	for _, p := range picks {
		f, err := os.Open(p.file)
		if err != nil { panic(err) }
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		var raw string
		for i := 1; sc.Scan(); i++ {
			if i == p.line { raw = sc.Text(); break }
		}
		f.Close()
		if strings.TrimSpace(raw) == "" { panic("empty " + p.file) }

		name := parser.DetectAll(raw)
		pr, _ := parser.Get(name)
		ev, err := pr.Parse(raw)
		if err != nil { panic(err) }
		if err := ev.Validate(); err != nil { panic(err) }

		out = append(out, hero{
			Vendor: name, Raw: ev.RawData,
			ClassUID: ev.ClassUID, ClassName: ev.ClassName,
			TypeUID: ev.TypeUID, TypeName: ev.TypeName,
			Severity: ev.Severity, SeverityID: ev.SeverityID,
			Action: ev.Action, Activity: ev.ActivityName,
			Finding: ev.FindingInfo, Confidence: ev.Confidence,
			SrcIP: ev.SrcEndpoint.IP, SrcPort: ev.SrcEndpoint.Port,
			DstIP: ev.DstEndpoint.IP, DstPort: ev.DstEndpoint.Port,
			Proto: ev.ProtocolName, Time: ev.Time,
			Hash: ev.RawDataHash, Size: ev.RawDataSize, UID: ev.EventID(),
			Unmapped: ev.Unmapped, Message: ev.Message,
		})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(map[string]any{"heroes": out})
}
