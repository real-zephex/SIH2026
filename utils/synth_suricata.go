package utils

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"
)

// GenerateSuricata returns n synthetic Suricata EVE JSONLines in the same
// shapes as samples/suricata_eve.json: mostly "alert" events across the ET
// categories seen in the samples, plus "http"/"dns"/"flow"/"tls" traffic
// events to exercise the parser's 4001 NetworkActivity path.
// seed=0 uses time-based randomness; pass a fixed seed for reproducible tests.
func GenerateSuricata(n int, seed int64) []string {
	if n <= 0 {
		return nil
	}
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	r := rand.New(rand.NewSource(seed))
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		b, err := json.Marshal(synthSuricata(r, i))
		if err != nil {
			continue
		}
		out = append(out, string(b))
	}
	return out
}

// WriteSuricataSamples writes n synthetic EVE JSONLines to path.
func WriteSuricataSamples(path string, n int, seed int64) error {
	lines := GenerateSuricata(n, seed)
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

type suricataAlert struct {
	Action      string `json:"action"`
	GID         int    `json:"gid"`
	SignatureID int    `json:"signature_id"`
	Rev         int    `json:"rev"`
	Signature   string `json:"signature"`
	Category    string `json:"category"`
	Severity    int    `json:"severity"`
}

type suricataFlow struct {
	PktsToServer  int64 `json:"pkts_toserver"`
	PktsToClient  int64 `json:"pkts_toclient"`
	BytesToServer int64 `json:"bytes_toserver"`
	BytesToClient int64 `json:"bytes_toclient"`
}

type suricataHTTP struct {
	Hostname  string `json:"hostname,omitempty"`
	URL       string `json:"url,omitempty"`
	UserAgent string `json:"http_user_agent,omitempty"`
	Method    string `json:"http_method,omitempty"`
	Status    int    `json:"status,omitempty"`
}

type suricataEve struct {
	Timestamp string        `json:"timestamp"`
	FlowID    int64         `json:"flow_id"`
	PcapCnt   int64         `json:"pcap_cnt"`
	EventType string        `json:"event_type"`
	SrcIP     string        `json:"src_ip"`
	SrcPort   int           `json:"src_port"`
	DestIP    string        `json:"dest_ip"`
	DestPort  int           `json:"dest_port"`
	Proto     string        `json:"proto"`
	AppProto  string        `json:"app_proto,omitempty"`
	Alert     suricataAlert `json:"alert,omitempty"`
	Flow      suricataFlow  `json:"flow,omitempty"`
	HTTP      suricataHTTP  `json:"http,omitempty"`
}

var suricataSigs = []struct {
	sig      string
	category string
	severity int
	sid      int
}{
	{"ET SCAN Potential SSH Scan", "Attempted Information Leak", 2, 2001219},
	{"ET SCAN Behavioral Unusual Port 445 traffic Potential Scan or Infection", "Misc activity", 3, 2001569},
	{"ET SCAN Behavioral Unusual Port 139 traffic Potential Scan or Infection", "Misc activity", 3, 2001579},
	{"ET MALWARE BTGrab.com Spyware Downloading Ads", "A Network Trojan was detected", 1, 2001999},
	{"ET TROJAN Possible Zeus Gameover Response", "A Network Trojan was detected", 1, 2018312},
	{"ET POLICY Outbound Frequent Tor Connection", "Potential Corporate Privacy Violation", 2, 2017930},
	{"ET POLICY DNS Query for TOR Hidden Domain", "Potential Corporate Privacy Violation", 2, 2017931},
	{"ET EXPLOIT Possible CVE-2017-0144 SMB RCE", "Attempted Administrator Privilege Gain", 1, 2024218},
	{"ET WEB_SERVER Suspicious POST to Login Endpoint", "Attempted Administrator Privilege Gain", 2, 2017764},
	{"ET INFO Successful SSH Login Bruteforced", "Successful Administrator Privilege Gain", 1, 2006546},
}

func synthSuricata(r *rand.Rand, i int) suricataEve {
	ts := suricataTimestamp(r)
	srcIP := fmt.Sprintf("10.%d.%d.%d", r.Intn(200)+10, r.Intn(250)+2, r.Intn(250)+2)
	dstIP := fmt.Sprintf("10.%d.%d.%d", 40+r.Intn(10), r.Intn(250)+2, r.Intn(250)+2)
	protos := []string{"TCP", "TCP", "TCP", "UDP"}
	proto := protos[r.Intn(len(protos))]
	dport := map[string]int{"TCP": []int{22, 80, 443, 445, 139}[r.Intn(5)], "UDP": []int{53, 137, 500}[r.Intn(3)]}[proto]
	n := 1 + r.Intn(8)
	e := suricataEve{
		Timestamp: ts,
		FlowID:    r.Int63n(900000000000000) + 100000,
		PcapCnt:   int64(100000 + i*37 + r.Intn(500)),
		SrcIP:     srcIP,
		SrcPort:   1024 + r.Intn(60000),
		DestIP:    dstIP,
		DestPort:  dport,
		Proto:     proto,
		Flow: suricataFlow{
			PktsToServer:  int64(n),
			PktsToClient:  int64(r.Intn(n + 1)),
			BytesToServer: int64(60 + r.Intn(4000)),
			BytesToClient: int64(r.Intn(8000)),
		},
	}

	// ~75% alerts (mirrors curated samples), ~25% plain traffic for the 4001 path.
	if r.Intn(4) < 3 {
		s := suricataSigs[r.Intn(len(suricataSigs))]
		e.EventType = "alert"
		e.Alert = suricataAlert{
			Action:      []string{"allowed", "allowed", "blocked"}[r.Intn(3)],
			GID:         1,
			SignatureID: s.sid,
			Rev:         1 + r.Intn(20),
			Signature:   s.sig,
			Category:    s.category,
			Severity:    s.severity,
		}
		if r.Intn(3) == 0 {
			e.AppProto = "http"
			e.HTTP = suricataHTTP{
				Hostname:  fmt.Sprintf("evil%d.example.com", r.Intn(900)+100),
				URL:       "/loader.exe",
				UserAgent: "Mozilla/5.0",
				Method:    "GET",
				Status:    200,
			}
		}
		return e
	}

	e.EventType = []string{"http", "dns", "flow", "tls"}[r.Intn(4)]
	e.AppProto = map[string]string{"http": "http", "dns": "dns", "flow": "", "tls": "tls"}[e.EventType]
	return e
}

// suricataTimestamp renders EVE-style timestamps ("2006-01-02T15:04:05.999999-0700").
// Uniquely named to avoid colliding with sibling synth helpers on merge.
func suricataTimestamp(r *rand.Rand) string {
	t := time.Date(2018, 3, 20+r.Intn(8),
		r.Intn(24), r.Intn(60), r.Intn(60), r.Intn(1e9),
		time.FixedZone("MDT", -6*3600))
	return t.Format("2006-01-02T15:04:05.999999-0700")
}
