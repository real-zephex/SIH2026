package parser

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"sih/src/schema"
)

// Suricata is the Suricata IDS/IPS EVE JSON parser (REQS.md #3).
// Sample: samples/suricata_eve.json (30 lines, JSONLines).
type Suricata struct{}

func init() { Register(Suricata{}) }

// Name returns the registry name.
func (Suricata) Name() string { return "suricata" }

// Detect is a cheap prefix sniff: EVE lines are JSON objects with "event_type".
// No JSON parsing here — Parse does the expensive work.
func (Suricata) Detect(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" || t[0] != '{' {
		return false
	}
	return strings.Contains(t, `"event_type"`)
}

// eveAlert mirrors the Suricata EVE "alert" sub-object (slim).
type eveAlert struct {
	Action      string `json:"action"`
	GID         int    `json:"gid"`
	SignatureID int    `json:"signature_id"`
	Rev         int    `json:"rev"`
	Signature   string `json:"signature"`
	Category    string `json:"category"`
	Severity    int    `json:"severity"`
}

// eveFlow mirrors the EVE "flow" counters (slim).
type eveFlow struct {
	PktsToServer  int64 `json:"pkts_toserver"`
	PktsToClient  int64 `json:"pkts_toclient"`
	BytesToServer int64 `json:"bytes_toserver"`
	BytesToClient int64 `json:"bytes_toclient"`
}

// eveHTTP mirrors the EVE "http" enrichment (slim, for Unmapped).
type eveHTTP struct {
	Hostname    string `json:"hostname"`
	URL         string `json:"url"`
	UserAgent   string `json:"http_user_agent"`
	Method      string `json:"http_method"`
	Status      int    `json:"status"`
	ContentType string `json:"http_content_type"`
}

// eve is the slim EVE JSONLine we parse. Unknown event_types still parse;
// only fields we map are decoded, the rest stays in RawData (lossless).
type eve struct {
	Timestamp string         `json:"timestamp"`
	EventType string         `json:"event_type"`
	SrcIP     string         `json:"src_ip"`
	DestIP    string         `json:"dest_ip"`
	SrcPort   int            `json:"src_port"`
	DestPort  int            `json:"dest_port"`
	Proto     string         `json:"proto"`
	AppProto  string         `json:"app_proto"`
	FlowID    int64          `json:"flow_id"`
	PcapCnt   int64          `json:"pcap_cnt"`
	Alert     eveAlert       `json:"alert"`
	Flow      eveFlow        `json:"flow"`
	HTTP      eveHTTP        `json:"http"`
	DNS       map[string]any `json:"dns"`
}

// ParseSuricata parses one EVE JSONLine into schema.Event.
//
//   - event_type "alert" -> OCSF 2004 DetectionFinding / Create, severity from
//     alert.severity (Suricata 1=highest).
//   - any other event_type (http, dns, flow, tls, ...) -> OCSF 4001
//     NetworkActivity / Allow (observed traffic, not a verdict).
func ParseSuricata(line string) (schema.Event, error) {
	raw := strings.TrimRight(line, "\r\n")
	if strings.TrimSpace(raw) == "" {
		return schema.Event{}, fmt.Errorf("suricata: empty line")
	}
	var e eve
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		return schema.Event{}, fmt.Errorf("suricata: invalid JSON: %w", err)
	}
	if e.EventType == "" {
		return schema.Event{}, fmt.Errorf("suricata: missing event_type")
	}

	uid := suricataUID()
	meta := schema.Metadata{
		Product:        schema.Product{Name: "Suricata", Vendor: "OISF", Version: "6.x"},
		Version:        schema.OCSFVersion,
		UID:            uid,
		CorrelationUID: uid,
	}

	isAlert := e.EventType == "alert"
	classUID := schema.ClassNetworkActivity
	activity := schema.ActivityAllow
	severity := schema.SeverityInfo
	msg := fmt.Sprintf("Suricata %s event", e.EventType)
	if isAlert {
		classUID = schema.ClassDetectionFinding
		activity = schema.ActivityCreate
		severity = suricataSeverity(e.Alert.Severity)
		if e.Alert.Signature != "" {
			msg = e.Alert.Signature
		}
	}

	ev := schema.NewEvent(classUID, activity, severity, suricataTime(e.Timestamp), meta, msg)

	if isAlert {
		ev.StatusID, ev.Status = schema.StatusOther, "Other"
		ev.Action = e.Alert.Action
		if ev.Action == "" {
			ev.Action = "Alert"
		}
		ev.FindingInfo = e.Alert.Signature
		if e.Alert.Category != "" {
			ev.Confidence = e.Alert.Category
		}
	} else {
		ev.StatusID, ev.Status = schema.StatusSuccess, "Success"
		ev.Action = e.EventType
	}

	ev.SrcEndpoint = schema.Endpoint{IP: strings.TrimSpace(e.SrcIP), Port: e.SrcPort}
	ev.DstEndpoint = schema.Endpoint{IP: strings.TrimSpace(e.DestIP), Port: e.DestPort}
	ev.ProtocolName, ev.ProtocolNum = suricataProto(e.Proto)
	ev.Direction = "unknown"
	ev.Traffic = schema.Traffic{
		Packets: e.Flow.PktsToServer + e.Flow.PktsToClient,
		Bytes:   e.Flow.BytesToServer + e.Flow.BytesToClient,
	}

	ev.RawData = raw
	ev.RawDataHash = schema.HashRaw(raw)
	ev.RawDataSize = len(raw)

	// Overflow vendor fields -> Unmapped (cap 20 per schema.Validate).
	um := map[string]string{
		"suricata.event_type": e.EventType,
	}
	if e.FlowID != 0 {
		um["suricata.flow_id"] = strconv.FormatInt(e.FlowID, 10)
	}
	if e.PcapCnt != 0 {
		um["suricata.pcap_cnt"] = strconv.FormatInt(e.PcapCnt, 10)
	}
	if e.AppProto != "" {
		um["suricata.app_proto"] = e.AppProto
	}
	if isAlert {
		if e.Alert.SignatureID != 0 {
			um["suricata.signature_id"] = strconv.Itoa(e.Alert.SignatureID)
		}
		if e.Alert.GID != 0 {
			um["suricata.gid"] = strconv.Itoa(e.Alert.GID)
		}
		if e.Alert.Rev != 0 {
			um["suricata.rev"] = strconv.Itoa(e.Alert.Rev)
		}
		if e.Alert.Category != "" {
			um["suricata.category"] = e.Alert.Category
		}
		if e.HTTP.Hostname != "" {
			um["http.hostname"] = e.HTTP.Hostname
		}
		if e.HTTP.URL != "" {
			um["http.url"] = e.HTTP.URL
		}
		if e.HTTP.UserAgent != "" {
			um["http.user_agent"] = e.HTTP.UserAgent
		}
	}
	// Validate IPs early with a clear error (schema.Validate would reject too).
	for _, ep := range []schema.Endpoint{ev.SrcEndpoint, ev.DstEndpoint} {
		if ep.IP != "" && net.ParseIP(ep.IP) == nil {
			return schema.Event{}, fmt.Errorf("suricata: invalid ip %q", ep.IP)
		}
	}
	ev.Unmapped = um

	if err := ev.Validate(); err != nil {
		return schema.Event{}, fmt.Errorf("suricata: %w", err)
	}
	return ev, nil
}

// Parse implements Parser.
func (Suricata) Parse(line string) (schema.Event, error) { return ParseSuricata(line) }

// suricataSeverity maps Suricata alert severity (1=highest .. 3+=low) to OCSF.
func suricataSeverity(s int) int {
	switch s {
	case 1:
		return schema.SeverityHigh
	case 2:
		return schema.SeverityMedium
	case 3:
		return schema.SeverityLow
	default:
		if s <= 0 {
			return schema.SeverityInfo
		}
		return schema.SeverityLow
	}
}

// suricataProto normalizes the EVE proto string to OCSF name + IANA number.
func suricataProto(p string) (string, int) {
	switch strings.ToUpper(strings.TrimSpace(p)) {
	case "TCP":
		return "tcp", 6
	case "UDP":
		return "udp", 17
	case "ICMP":
		return "icmp", 1
	case "":
		return "", 0
	default:
		return strings.ToLower(p), 0
	}
}

// suricataTime parses EVE timestamps like "2018-03-24T14:37:19.037299-0600".
// Falls back to NowMillis so Validate's time>0 never fails on odd input.
func suricataTime(ts string) int64 {
	layouts := []string{
		"2006-01-02T15:04:05.999999999-0700",
		"2006-01-02T15:04:05.999999999Z07:00",
		time.RFC3339Nano,
		time.RFC3339,
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, ts); err == nil {
			return t.UTC().UnixMilli()
		}
	}
	return schema.NowMillis()
}

// suricataUID generates a UUID v4-style trace ID.
// Named uniquely to avoid colliding with sibling parsers' helpers on merge.
func suricataUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
