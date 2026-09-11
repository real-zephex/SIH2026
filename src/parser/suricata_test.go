package parser

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sih/src/schema"
	"sih/utils"
)

func TestSuricataDetect(t *testing.T) {
	pos := `{"timestamp":"2018-03-24T14:37:19.037299-0600","event_type":"alert","src_ip":"10.0.0.1"}`
	if !(Suricata{}).Detect(pos) {
		t.Fatalf("should detect EVE alert line")
	}
	// Leading whitespace is fine.
	if !(Suricata{}).Detect("  " + pos) {
		t.Fatalf("should detect with leading whitespace")
	}
	neg := []string{
		``,
		`   `,
		`<134>Nov 28 2007 17:20:48: %ASA-6-302013: Built outbound TCP connection 1`,
		`<190>date=2019-05-15 time=18:03:36 logid="1059028704" type="utm"`,
		`LEEF:1.0|Palo Alto Networks|PAN-OS|8.1.6|threat|`,
		`CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|Traffic Log|1|src=1.2.3.4`,
		`{"timestamp":"x","src_ip":"1.2.3.4"}`,
		`not json at all`,
	}
	for _, l := range neg {
		if (Suricata{}).Detect(l) {
			t.Fatalf("false positive detect: %q", l)
		}
	}
}

func TestSuricataParseSamples(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "samples", "suricata_eve.json"))
	if err != nil {
		t.Fatalf("read samples: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 30 {
		t.Fatalf("want 30 sample lines, got %d", len(lines))
	}
	count := 0
	for i, ln := range lines {
		if !(Suricata{}).Detect(ln) {
			t.Fatalf("line %d not detected", i+1)
		}
		e, err := (Suricata{}).Parse(ln)
		if err != nil {
			t.Fatalf("line %d parse: %v", i+1, err)
		}
		if err := e.Validate(); err != nil {
			t.Fatalf("line %d validate: %v", i+1, err)
		}
		// All curated samples are alerts -> 2004 findings.
		if e.ClassUID != schema.ClassDetectionFinding {
			t.Fatalf("line %d: want class 2004, got %d", i+1, e.ClassUID)
		}
		if e.TypeUID != 200401 {
			t.Fatalf("line %d: want type_uid 200401, got %d", i+1, e.TypeUID)
		}
		if e.RawData == "" || e.EventID() == "" {
			t.Fatalf("line %d missing raw/uid", i+1)
		}
		if e.RawDataHash != schema.HashRaw(e.RawData) {
			t.Fatalf("line %d bad raw hash", i+1)
		}
		if e.SrcEndpoint.IP == "" || e.DstEndpoint.IP == "" {
			t.Fatalf("line %d missing endpoints: %+v", i+1, e)
		}
		if e.FindingInfo == "" {
			t.Fatalf("line %d missing finding_info (signature)", i+1)
		}
		b, _ := json.Marshal(e)
		t.Logf("line %d sig=%q src=%s:%d dst=%s:%d proto=%s",
			i+1, e.FindingInfo,
			e.SrcEndpoint.IP, e.SrcEndpoint.Port,
			e.DstEndpoint.IP, e.DstEndpoint.Port,
			e.ProtocolName)
		_ = b
		count++
	}
	t.Logf("Ran %d tests", count)
}

func TestSuricataParseKnownAlert(t *testing.T) {
	// First line of samples/suricata_eve.json: ET SCAN Potential SSH Scan.
	line := `{"timestamp": "2018-03-24T14:37:19.037299-0600", "flow_id": 928532049924531, "pcap_cnt": 169577, "event_type": "alert", "src_ip": "0.0.0.0", "src_port": 26078, "dest_ip": "10.47.8.150", "dest_port": 22, "proto": "TCP", "alert": {"action": "allowed", "gid": 1, "signature_id": 2001219, "rev": 20, "signature": "ET SCAN Potential SSH Scan", "category": "Attempted Information Leak", "severity": 2}, "flow": {"pkts_toserver": 1, "pkts_toclient": 0, "bytes_toserver": 74, "bytes_toclient": 0, "start": "2018-03-24T14:37:19.037299-0600"}}`
	e, err := ParseSuricata(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.SrcEndpoint.IP != "0.0.0.0" || e.SrcEndpoint.Port != 26078 {
		t.Fatalf("bad src: %+v", e.SrcEndpoint)
	}
	if e.DstEndpoint.IP != "10.47.8.150" || e.DstEndpoint.Port != 22 {
		t.Fatalf("bad dst: %+v", e.DstEndpoint)
	}
	if e.ProtocolName != "tcp" || e.ProtocolNum != 6 {
		t.Fatalf("bad proto: %q %d", e.ProtocolName, e.ProtocolNum)
	}
	if e.FindingInfo != "ET SCAN Potential SSH Scan" {
		t.Fatalf("bad signature: %q", e.FindingInfo)
	}
	if e.SeverityID != schema.SeverityMedium { // Suricata sev 2 -> Medium
		t.Fatalf("bad severity: %d", e.SeverityID)
	}
	if e.Traffic.Bytes != 74 || e.Traffic.Packets != 1 {
		t.Fatalf("bad traffic: %+v", e.Traffic)
	}
	if e.Unmapped["suricata.signature_id"] != "2001219" {
		t.Fatalf("missing unmapped signature_id: %v", e.Unmapped)
	}
	// 2018-03-24T14:37:19.037299-0600 == 1521923839037 ms UTC.
	if e.Time != 1521923839037 {
		t.Fatalf("bad time: got %d", e.Time)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestSuricataParseNonAlert(t *testing.T) {
	// http event_type -> 4001 NetworkActivity.
	line := `{"timestamp":"2018-03-24T14:35:03.195686-0600","event_type":"http","src_ip":"10.47.42.68","src_port":49943,"dest_ip":"64.135.77.30","dest_port":80,"proto":"TCP","app_proto":"http"}`
	e, err := ParseSuricata(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.ClassUID != schema.ClassNetworkActivity || e.TypeUID != 400101 {
		t.Fatalf("want 4001/400101, got %d/%d", e.ClassUID, e.TypeUID)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestSuricataParseRejects(t *testing.T) {
	for _, tc := range []string{
		``,
		`not json`,
		`{"src_ip":"1.2.3.4"}`,
		`{"event_type":"alert","src_ip":"999.999.999.999","dest_ip":"1.2.3.4","timestamp":"2018-03-24T14:37:19.037299-0600","proto":"TCP"}`,
	} {
		if _, err := ParseSuricata(tc); err == nil {
			t.Fatalf("expected error for %q", tc)
		}
	}
}

func TestSuricataRegistry(t *testing.T) {
	p, ok := Get("suricata")
	if !ok {
		t.Fatal("suricata not registered")
	}
	line := `{"timestamp":"2018-03-24T14:37:19.037299-0600","event_type":"alert","src_ip":"10.0.0.1","src_port":1,"dest_ip":"10.0.0.2","dest_port":80,"proto":"TCP","alert":{"signature":"x","severity":2}}`
	if got := DetectAll(line); got != "suricata" {
		t.Fatalf("DetectAll=%q, want suricata", got)
	}
	e, err := p.Parse(line)
	if err != nil {
		t.Fatalf("registry parse: %v", err)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("registry validate: %v", err)
	}
}

func TestSuricataSynthetic(t *testing.T) {
	lines := utils.GenerateSuricata(100000, 42)

	// if len(lines) != 200 {
	// 	t.Fatalf(
	// 		"generated %d lines, want 200",
	// 		len(lines),
	// 	)
	// }

	count := 0
	seen := map[int]int{}

	for i, line := range lines {
		if !(Suricata{}).Detect(line) {
			t.Fatalf(
				"synthetic line %d: Detect returned false\nraw: %.160s",
				i+1,
				line,
			)
		}

		event, err := (Suricata{}).Parse(line)
		if err != nil {
			t.Fatalf(
				"synthetic line %d: Parse failed: %v\nraw: %.160s",
				i+1,
				err,
				line,
			)
		}

		if err := event.Validate(); err != nil {
			t.Fatalf(
				"synthetic line %d: Validate failed: %v\nraw: %.160s",
				i+1,
				err,
				line,
			)
		}

		if event.RawData != line {
			t.Fatalf(
				"synthetic line %d: raw_data was not preserved",
				i+1,
			)
		}

		seen[event.ClassUID]++
		count++
	}

	// Generator must cover both classes: 2004 findings and 4001 traffic.
	if seen[schema.ClassDetectionFinding] == 0 {
		t.Fatal("synthetic set has no 2004 DetectionFinding events")
	}

	if seen[schema.ClassNetworkActivity] == 0 {
		t.Fatal("synthetic set has no 4001 NetworkActivity events")
	}

	t.Logf("Processed %d log entries", count)
}
