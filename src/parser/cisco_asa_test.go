package parser

import (
	"encoding/json"
	"sih/utils"
	"testing"
)

func TestCiscoDetect(t *testing.T) {
	neg := []string{
		`<190>date=2019-05-15 time=18:03:36 logid="1059028704" type="utm"`,
		`{"event_type":"alert","src_ip":"1.2.3.4"}`,
		`LEEF:1.0|Palo Alto Networks|PAN-OS|8.1.6|threat|`,
		``,
	}
	for _, l := range neg {
		if (CiscoASA{}).Detect(l) {
			t.Fatalf("false positive detect: %q", l)
		}
	}
}

func TestCiscoParseSamples(t *testing.T) {
	// raw, err := os.ReadFile("../../samples/cisco_asa.log")
	// if err != nil {
	// 	t.Fatalf("read samples: %v", err)
	// }
	// lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	lines := utils.GenerateCiscoASA(1000, 0)
	count := 0
	// if len(lines) != 20 {
	// 	t.Fatalf("want 20 sample lines, got %d", len(lines))
	// }
	for i, ln := range lines {
		if !(CiscoASA{}).Detect(ln) {
			t.Fatalf("line %d not detected: %q", i+1, ln)
		}
		e, err := (CiscoASA{}).Parse(ln)
		if err != nil {
			t.Fatalf("line %d parse: %v\n%s", i+1, err, ln)
		}
		if err := e.Validate(); err != nil {
			t.Fatalf("line %d validate: %v", i+1, err)
		}
		if e.ClassUID != 4001 || e.RawData == "" || e.EventID() == "" {
			t.Fatalf("line %d missing class/raw/uid", i+1)
		}
		b, _ := json.Marshal(e)
		t.Logf("line %d class=%d activity=%d src=%s:%d dst=%s:%d proto=%s action=%s\n  in:  %s\n  out: %s",
			i+1, e.ClassUID, e.ActivityID,
			e.SrcEndpoint.IP, e.SrcEndpoint.Port,
			e.DstEndpoint.IP, e.DstEndpoint.Port,
			e.ProtocolName, e.Action, ln, string(b))
		count++
		// TODO(you): strengthen per-ID asserts, e.g. line 2 (302013):
		// want src 192.168.20.31/3530, dst 207.68.178.45/80, proto tcp, Allow.
	}
	t.Logf("Processed %d log entries", count)
}

func TestCiscoRegistry(t *testing.T) {
	p, ok := Get("cisco_asa")
	if !ok {
		t.Fatal("cisco_asa not registered")
	}
	if got := DetectAll("%ASA-6-302013: Built outbound TCP connection 1"); got != "cisco_asa" {
		t.Fatalf("DetectAll=%q", got)
	}
	_ = p
}
