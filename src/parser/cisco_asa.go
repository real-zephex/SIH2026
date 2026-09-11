package parser

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sih/src/schema"
)

// CiscoASA is the Cisco ASA firewall Syslog parser (REQS.md #1).
// Sample: samples/cisco_asa.log (20 lines).
type CiscoASA struct{}

func init() { Register(CiscoASA{}) }

// Name returns the registry name.
func (CiscoASA) Name() string { return "cisco_asa" }

// determine whether the log file is a CISCO file by checking for string %ASA
// in the line.
func (CiscoASA) Detect(line string) bool { return strings.Contains(line, "%ASA-") }

var (
	asaHeader = regexp.MustCompile(`%ASA-(\d)-(\d+):\s*(.*)`)
	// inside:1.2.3.4/5678 | outside:1.2.3.4/80 | inside/1.2.3.4(5678)
	asaNamedEP = regexp.MustCompile(`(inside|outside):([0-9.]+)(?:/(\d+))?`)
	asaSlashEP = regexp.MustCompile(`(inside|outside)/([0-9.]+)\((\d+)\)`)
	asaBareEP  = regexp.MustCompile(`from\s+([0-9]+\.[0-9.]+)(?:/(\d+))?`)
	asaProto   = regexp.MustCompile(`(?i)\b(TCP|UDP|ICMP)\b`)
	asaConnID  = regexp.MustCompile(`connection\s+(\d+)`)
	asaToEP    = regexp.MustCompile(`to\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(?:/(\d+))?`)
	asaForIP   = regexp.MustCompile(`for IP\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)`)
)

// ParseCiscoASA parses one ASA syslog line into schema.Event (OCSF 4001).
// Baseline handles header + endpoints + proto + activity/severity mapping.
// TODO(you): tighten per-ID fields —
//   - 302013/302015/302018/305011 -> Allow, direction outbound/inbound
//   - 302014/302016/302021/305012 -> Allow teardown (Status Success, bytes in Unmapped)
//   - 106023/106015/313004/305006/402119/110002 -> Deny (Status Failure)
//   - 106100 permit vs deny by verb; 725001/2 SSL, 602101 PMTU, 111008/750002 mgmt
func ParseCiscoASA(line string) (schema.Event, error) {
	raw := strings.TrimRight(line, "\r\n")
	m := asaHeader.FindStringSubmatch(raw)
	if m == nil {
		return schema.Event{}, fmt.Errorf("cisco_asa: no %%ASA-sev-id header: %q", trunc(raw, 80))
	}
	asaSev, _ := strconv.Atoi(m[1])
	msgID := m[2]
	msg := m[3]

	uid := newUID()
	meta := schema.Metadata{
		Product:        schema.Product{Name: "ASA", Vendor: "Cisco", Version: "9.x"},
		Version:        schema.OCSFVersion,
		UID:            uid,
		CorrelationUID: uid,
	}
	e := schema.NewEvent(schema.ClassNetworkActivity, activityForID(msgID, msg), severityForASA(asaSev), parseTime(raw), meta, msg)
	e.StatusID, e.Status = statusForID(msg)
	e.Action = actionForID(msgID, msg)
	e.ProtocolName, e.ProtocolNum = protoOf(raw)
	e.Direction = directionOf(raw)
	e.SrcEndpoint, e.DstEndpoint = endpointsOf(raw)
	e.Traffic = trafficOf(raw)
	e.RawData = raw
	e.RawDataHash = schema.HashRaw(raw)
	e.RawDataSize = len(raw)
	e.Unmapped = map[string]string{"asa.message_id": msgID, "asa.severity": m[1]}
	if id := asaConnID.FindStringSubmatch(raw); id != nil {
		e.Unmapped["asa.connection_id"] = id[1]
	}
	// TODO(you): add per-ID extras, e.g. bytes/duration for 302014/302016,
	// hit-cnt for 106100, SPI for 402119. Keep Unmapped <= 20 keys.
	if err := e.Validate(); err != nil {
		return schema.Event{}, fmt.Errorf("cisco_asa %s: %w", msgID, err)
	}
	return e, nil
}

// Parse implements Parser.
func (CiscoASA) Parse(line string) (schema.Event, error) { return ParseCiscoASA(line) }

// --- mapping helpers (extend here) ---

func activityForID(id, msg string) int {
	switch id {
	case "106023", "106015", "313004", "313005", "305006", "402119", "110002":
		return schema.ActivityDeny
	case "302013", "302015", "302018", "302021", "305011", "305012",
		"302014", "302016", "725001", "725002", "602101":
		l := strings.ToLower(msg)
		if strings.Contains(l, "deny") || strings.Contains(l, "denied") || strings.Contains(l, "failed") {
			return schema.ActivityDeny
		}
		return schema.ActivityAllow
	case "106100":
		if strings.Contains(strings.ToLower(msg), "denied") {
			return schema.ActivityDeny
		}
		return schema.ActivityAllow
	default:
		l := strings.ToLower(msg)
		if strings.Contains(l, "deny") || strings.Contains(l, "denied") || strings.Contains(l, "failed") {
			return schema.ActivityDeny
		}
		if strings.Contains(l, "built") || strings.Contains(l, "permitted") || strings.Contains(l, "allow") {
			return schema.ActivityAllow
		}
		return schema.ActivityUnknown
	}
}

func statusForID(msg string) (int, string) {
	l := strings.ToLower(msg)
	if strings.Contains(l, "deny") || strings.Contains(l, "denied") || strings.Contains(l, "failed") || strings.Contains(l, "error") {
		return schema.StatusFailure, "Failure"
	}
	return schema.StatusSuccess, "Success"
}

func actionForID(id, msg string) string {
	// Keep vendor verb for OCSF action; first word of message is usually it.
	f := strings.Fields(msg)
	if len(f) == 0 {
		return "Unknown-" + id
	}
	verb := f[0]
	switch strings.ToLower(verb) {
	case "built":
		return "Built"
	case "teardown":
		return "Teardown"
	case "deny", "denied":
		return "Deny"
	case "permitted":
		return "Permit"
	default:
		return verb
	}
}

// severityForASA maps ASA 0-7 syslog severity to OCSF 0-5.
func severityForASA(asa int) int {
	switch asa {
	case 0, 1:
		return schema.SeverityFatal
	case 2, 3:
		return schema.SeverityHigh
	case 4:
		return schema.SeverityMedium
	case 5:
		return schema.SeverityLow
	default:
		return schema.SeverityInfo
	}
}

func protoOf(raw string) (string, int) {
	m := asaProto.FindStringSubmatch(raw)
	if m == nil {
		return "", 0
	}
	switch strings.ToUpper(m[1]) {
	case "TCP":
		return "tcp", 6
	case "UDP":
		return "udp", 17
	case "ICMP":
		return "icmp", 1
	}
	return strings.ToLower(m[1]), 0
}

func directionOf(raw string) string {
	l := strings.ToLower(raw)
	switch {
	case strings.Contains(l, "outbound"):
		return "outbound"
	case strings.Contains(l, "inbound"):
		return "inbound"
	default:
		return "unknown"
	}
}

// endpointsOf extracts src/dst. Convention: first named endpoint = src side
// listed, second = dst side; "for outside:X to inside:Y" keeps raw order so the
// cross-vendor query (src_ip/dst_ip) stays consistent per-line.
// TODO(you): normalize direction so inside always = src for outbound flows.
func endpointsOf(raw string) (src, dst schema.Endpoint) {
	var eps []schema.Endpoint
	for _, m := range asaNamedEP.FindAllStringSubmatch(raw, -1) {
		if e := ep(m[2], m[3]); e.IP != "" {
			eps = append(eps, e)
		}
	}
	for _, m := range asaSlashEP.FindAllStringSubmatch(raw, -1) {
		if e := ep(m[2], m[3]); e.IP != "" {
			eps = append(eps, e)
		}
	}

	if len(eps) >= 2 {
		return eps[len(eps)-2], eps[len(eps)-1]
	}
	fromM := asaBareEP.FindStringSubmatch(raw)
	var from schema.Endpoint
	hasFrom := false
	if fromM != nil {
		if e := ep(fromM[1], fromM[2]); e.IP != "" {
			from, hasFrom = e, true
		}
	}
	var to schema.Endpoint
	hasTo := false
	for _, m := range asaToEP.FindAllStringSubmatch(raw, -1) {
		if e := ep(m[1], m[2]); e.IP != "" {
			to, hasTo = e, true
		}
	}
	if len(eps) == 1 && hasTo {
		return eps[0], to
	}
	if len(eps) == 1 {
		return eps[0], schema.Endpoint{}
	}
	if hasFrom && hasTo {
		return from, to
	}
	if hasFrom {
		return from, schema.Endpoint{}
	}
	if hasTo {
		return schema.Endpoint{}, to
	}
	if m := asaForIP.FindStringSubmatch(raw); m != nil {
		if e := ep(m[1], ""); e.IP != "" {
			return schema.Endpoint{}, e
		}
	}
	return schema.Endpoint{}, schema.Endpoint{}
}

func ep(ip, port string) schema.Endpoint {
	if net.ParseIP(ip) == nil {
		return schema.Endpoint{}
	}
	p := 0
	if port != "" {
		p, _ = strconv.Atoi(port)
	}
	return schema.Endpoint{IP: ip, Port: p}
}

func trafficOf(raw string) schema.Traffic {
	// TODO(you): parse "bytes N" + "duration H:MM:SS" for 302014/302016/302021.
	l := strings.ToLower(raw)
	if strings.Contains(l, "bytes ") {
		var b int64
		fmt.Sscanf(l[strings.Index(l, "bytes "):], "bytes %d", &b)
		return schema.Traffic{Bytes: b}
	}
	return schema.Traffic{}
}

func parseTime(raw string) int64 {
	// Try "Oct 10 2018 12:34:56" and "Nov 28 2007 17:20:48" prefixes; else now.
	layouts := []string{"Jan 2 2006 15:04:05", "Jan _2 2006 15:04:05"}
	clean := strings.TrimLeft(raw, "<0123456789> ")
	for _, l := range layouts {
		if len(clean) >= 20 {
			if t, err := time.Parse(l, clean[:20]); err == nil {
				return t.UTC().UnixMilli()
			}
		}
	}
	return schema.NowMillis()
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
