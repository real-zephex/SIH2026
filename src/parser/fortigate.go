package parser

import (
	"crypto/rand"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"sih/src/schema"
)

// Detect identifies FortiGate key=value logs.
//
// We intentionally do not require srcip= because FortiGate system events
// such as line 6 in our samples may contain logid= and type= but no IP.
func Detect(line string) bool {
	return strings.Contains(line, "logid=") &&
		strings.Contains(line, "type=")
}

// stripPRI removes a syslog PRI prefix such as <190>.
func stripPRI(s string) string {
	if len(s) > 0 && s[0] == '<' {
		if end := strings.IndexByte(s, '>'); end >= 0 {
			return s[end+1:]
		}
	}

	return s
}

// tokenizeKV parses FortiGate key=value fields.
//
// Values may be quoted and contain spaces, commas, colons, etc.
// Example:
//
//	msg="Web.Client: HTTPS.BROWSER,"
//
// becomes:
//
//	msg -> Web.Client: HTTPS.BROWSER,
func tokenizeKV(s string) map[string]string {
	result := make(map[string]string)

	i := 0

	for i < len(s) {
		// Skip whitespace.
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}

		if i >= len(s) {
			break
		}

		// Find '=' separating key and value.
		keyStart := i

		for i < len(s) && s[i] != '=' &&
			s[i] != ' ' && s[i] != '\t' {
			i++
		}

		if i >= len(s) || s[i] != '=' {
			// Skip malformed token.
			for i < len(s) && s[i] != ' ' && s[i] != '\t' {
				i++
			}
			continue
		}

		key := s[keyStart:i]
		i++ // skip '='

		if i >= len(s) {
			result[key] = ""
			break
		}

		var value string

		// Quoted value.
		if s[i] == '"' {
			i++

			var b strings.Builder

			for i < len(s) {
				if s[i] == '"' {
					i++
					break
				}

				// Handle simple escaped characters.
				if s[i] == '\\' && i+1 < len(s) {
					switch s[i+1] {
					case '"', '\\':
						b.WriteByte(s[i+1])
						i += 2
						continue
					}
				}

				b.WriteByte(s[i])
				i++
			}

			value = b.String()
		} else {
			// Unquoted value ends at whitespace.
			valueStart := i

			for i < len(s) && s[i] != ' ' && s[i] != '\t' {
				i++
			}

			value = s[valueStart:i]
		}

		result[key] = value
	}

	return result
}

// Parse converts one FortiGate log line into the canonical ULPF event.
func Parse(line string) (schema.Event, error) {
	raw := line

	kv := tokenizeKV(stripPRI(line))

	if kv["logid"] == "" || kv["type"] == "" {
		return schema.Event{}, fmt.Errorf("not a FortiGate log")
	}

	// Timestamp.
	tsMillis, err := fortiGateTime(kv)
	if err != nil {
		return schema.Event{}, err
	}

	// Default to Network Activity.
	classUID := schema.ClassNetworkActivity

	// UTM virus/IPS events that were blocked/dropped become
	// Detection Findings.
	if strings.EqualFold(kv["type"], "utm") &&
		(strings.EqualFold(kv["subtype"], "virus") ||
			strings.EqualFold(kv["subtype"], "ips")) &&
		(strings.EqualFold(kv["action"], "blocked") ||
			strings.EqualFold(kv["action"], "dropped")) {
		classUID = schema.ClassDetectionFinding
	}

	// Map FortiGate action to canonical activity.
	//
	// IMPORTANT:
	// blocked/dropped return ActivityDetect.
	// schema.NewEvent() converts ActivityDetect to:
	//   4001 -> Deny
	//   2004 -> Create
	activity := fortiGateActivity(kv["action"])

	// Map FortiGate severity.
	severity := fortiGateSeverity(kv["level"])

	// Required metadata.
	meta := schema.Metadata{
		Product: schema.Product{
			Name:    "FortiGate",
			Vendor:  "Fortinet",
			Version: kv["version"],
		},
		Version: schema.OCSFVersion,
		UID:     newUID(),
	}

	// Prefer msg; fall back to logdesc.
	msg := kv["msg"]
	if msg == "" {
		msg = kv["logdesc"]
	}

	event := schema.NewEvent(
		classUID,
		activity,
		severity,
		tsMillis,
		meta,
		msg,
	)

	// Lossless raw-data fields.
	event.RawData = raw
	event.RawDataHash = schema.HashRaw(raw)
	event.RawDataSize = len(raw)

	// Source endpoint.
	event.SrcEndpoint.IP = kv["srcip"]
	event.SrcEndpoint.Port = parseInt(kv["srcport"])

	// Destination endpoint.
	event.DstEndpoint.IP = kv["dstip"]
	event.DstEndpoint.Port = parseInt(kv["dstport"])

	// Protocol.
	event.ProtocolNum = parseInt(kv["proto"])
	event.ProtocolName = fortiGateProtocol(kv["proto"], kv["service"])

	// Normalized network fields.
	event.Direction = kv["direction"]
	event.Action = kv["action"]

	event.Traffic.Bytes = parseInt64(kv["bytes"])
	event.Traffic.Packets = parseInt64(kv["packets"])

	// Finding information.
	if classUID == schema.ClassDetectionFinding {
		if kv["virus"] != "" {
			event.FindingInfo = kv["virus"]
		} else if kv["attack"] != "" {
			event.FindingInfo = kv["attack"]
		}
	}

	// Preserve fields that do not have a dedicated canonical field.
	event.Unmapped = make(map[string]string)

	known := map[string]bool{
		"date":      true,
		"time":      true,
		"logid":     true,
		"type":      true,
		"subtype":   true,
		"eventtype": true,
		"level":     true,
		"vd":        true,
		"eventtime": true,

		"srcip":   true,
		"dstip":   true,
		"srcport": true,
		"dstport": true,

		"proto":     true,
		"service":   true,
		"action":    true,
		"direction": true,

		"bytes":   true,
		"packets": true,

		"msg":     true,
		"logdesc": true,

		"virus":  true,
		"attack": true,
	}

	keys := make([]string, 0, len(kv))

	for key := range kv {
		if !known[key] {
			keys = append(keys, key)
		}
	}

	// Deterministic output.
	sort.Strings(keys)

	// PS requires unmapped fields to be capped at 20.
	for _, key := range keys {
		if len(event.Unmapped) >= 20 {
			break
		}

		event.Unmapped[key] = kv[key]
	}

	return event, nil
}

// parseInt converts a decimal string into int.
//
// Invalid or missing values become zero rather than causing
// the whole log to fail.
func parseInt(s string) int {
	if s == "" {
		return 0
	}

	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}

	return n
}

// parseInt64 converts a decimal string into int64.
//
// Invalid or missing values become zero.
func parseInt64(s string) int64 {
	if s == "" {
		return 0
	}

	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}

	return n
}

// fortiGateActivity maps FortiGate actions to OCSF activities.
//
// IMPORTANT:
// blocked/dropped must map to ActivityDetect here.
//
// For a Detection Finding (class 2004), schema.NewEvent()
// transforms ActivityDetect into ActivityCreate.
func fortiGateActivity(action string) int {
	switch strings.ToLower(action) {
	case "pass", "accept", "allow", "login", "ssl-login":
		return schema.ActivityAllow

	case "deny":
		return schema.ActivityDeny

	case "blocked", "dropped":
		return schema.ActivityDetect

	default:
		return schema.ActivityUnknown
	}
}

// fortiGateSeverity maps FortiGate levels to OCSF severity IDs.
func fortiGateSeverity(level string) int {
	switch strings.ToLower(level) {
	case "information", "notice":
		return schema.SeverityInfo

	case "low":
		return schema.SeverityLow

	case "warning", "medium":
		return schema.SeverityMedium

	case "alert", "high":
		return schema.SeverityHigh

	case "critical":
		return schema.SeverityFatal

	default:
		return schema.SeverityUnknown
	}
}

// fortiGateProtocol maps FortiGate protocol numbers to names.
//
// Unknown numeric protocols fall back to the FortiGate service name.
func fortiGateProtocol(proto, service string) string {
	switch proto {
	case "6":
		return "tcp"

	case "17":
		return "udp"

	case "1":
		return "icmp"
	}

	if service != "" {
		return strings.ToLower(service)
	}

	return ""
}

// fortiGateTime parses the FortiGate event timestamp.
//
// eventtime is preferred because it is already an epoch timestamp.
// date + time is used as a fallback.
func fortiGateTime(kv map[string]string) (int64, error) {
	if kv["eventtime"] != "" {
		seconds, err := strconv.ParseInt(kv["eventtime"], 10, 64)
		if err == nil {
			return seconds * 1000, nil
		}
	}

	if kv["date"] != "" && kv["time"] != "" {
		t, err := time.ParseInLocation(
			"2006-01-02 15:04:05",
			kv["date"]+" "+kv["time"],
			time.UTC,
		)

		if err != nil {
			return 0, fmt.Errorf(
				"parse FortiGate timestamp: %w",
				err,
			)
		}

		return t.UnixMilli(), nil
	}

	return 0, fmt.Errorf(
		"FortiGate log has no valid timestamp",
	)
}

// newUID generates a UUID v4-style trace ID using crypto/rand.
func newUID() string {
	b := make([]byte, 16)

	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}

	// UUID version 4.
	b[6] = (b[6] & 0x0f) | 0x40

	// UUID variant.
	b[8] = (b[8] & 0x3f) | 0x80

	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		b[0:4],
		b[4:6],
		b[6:8],
		b[8:10],
		b[10:16],
	)
}