package parser

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sih/src/schema"
)

// DetectLinux performs a cheap check to determine whether a line
// looks like a Linux firewall, netfilter, or SSH log.
func DetectLinux(line string) bool {
	return (strings.Contains(line, "SRC=") && strings.Contains(line, "DST=")) ||
		strings.Contains(line, "[UFW") ||
		strings.Contains(line, "[IPTABLES-DROP]") ||
		strings.Contains(line, "sshd[")
}

// ParseLinux parses Linux firewall/netfilter/SSH logs into the
// canonical ULPF OCSF-Slim Event.
func ParseLinux(line string) (schema.Event, error) {
	line = strings.TrimSpace(line)

	if line == "" {
		return schema.Event{}, fmt.Errorf("empty Linux log line")
	}

	// -----------------------------------------------------------------
	// 1. Determine event type/action
	// -----------------------------------------------------------------

	action := "UNKNOWN"
	severity := schema.SeverityInfo

	switch {
	case strings.Contains(line, "[UFW BLOCK]"):
		action = "BLOCK"
		severity = schema.SeverityLow

	case strings.Contains(line, "[IPTABLES-DROP]"):
		action = "DROP"
		severity = schema.SeverityLow

	case strings.Contains(line, "[UFW ALLOW]"):
		action = "ALLOW"

	case strings.Contains(line, "Failed password"):
		action = "FAIL"

	case strings.Contains(line, "Accepted password"):
		action = "ACCEPT"

	case strings.Contains(line, "[NEW SSH]"):
		action = "NEW"
	}

	// -----------------------------------------------------------------
	// 2. Timestamp
	// -----------------------------------------------------------------

	timestamp := linuxTimestamp(line)

	// -----------------------------------------------------------------
	// 3. Metadata / Event ID
	// -----------------------------------------------------------------

	eventID := extractField(line, "ID")

	// If the source did not provide an ID, use the SHA-256 of the
	// original line as a deterministic unique identifier.
	if eventID == "" {
		eventID = schema.HashRaw(line)
	}

	meta := schema.Metadata{
		Product: schema.Product{
			Name:    "Linux",
			Vendor:  "Linux",
			Version: "",
		},
		Version: schema.OCSFVersion,
		UID:     eventID,
	}

	// -----------------------------------------------------------------
	// 4. Create the canonical OCSF NetworkActivity event
	// -----------------------------------------------------------------

	event := schema.NewEvent(
		schema.ClassNetworkActivity,
		activityForLinuxAction(action),
		severity,
		timestamp,
		meta,
		line,
	)

	// -----------------------------------------------------------------
	// 5. Lossless raw-data fields
	// -----------------------------------------------------------------

	event.RawData = line
	event.RawDataHash = schema.HashRaw(line)
	event.RawDataSize = len(line)

	// -----------------------------------------------------------------
	// 6. Extract network information
	// -----------------------------------------------------------------

	srcIP := extractField(line, "SRC")
	dstIP := extractField(line, "DST")

	srcPort := parseIntField(line, "SPT")
	dstPort := parseIntField(line, "DPT")

	proto := strings.ToUpper(extractField(line, "PROTO"))

	event.SrcEndpoint = schema.Endpoint{
		IP:   srcIP,
		Port: srcPort,
	}

	event.DstEndpoint = schema.Endpoint{
		IP:   dstIP,
		Port: dstPort,
	}

	event.ProtocolName = proto

	// -----------------------------------------------------------------
	// 7. Protocol number
	// -----------------------------------------------------------------

	event.ProtocolNum = protocolNumber(proto)

	// -----------------------------------------------------------------
	// 8. Direction
	// -----------------------------------------------------------------

	event.Direction = linuxDirection(line)

	// -----------------------------------------------------------------
	// 9. Action
	// -----------------------------------------------------------------

	event.Action = action

	// -----------------------------------------------------------------
	// 10. Message
	// -----------------------------------------------------------------

	event.Message = linuxMessage(line)

	// -----------------------------------------------------------------
	// 11. Store useful Linux-specific fields in unmapped
	// -----------------------------------------------------------------

	event.Unmapped = make(map[string]string)

	addUnmapped(event.Unmapped, "hostname", linuxHostname(line))
	addUnmapped(event.Unmapped, "interface_in", extractField(line, "IN"))
	addUnmapped(event.Unmapped, "interface_out", extractField(line, "OUT"))
	addUnmapped(event.Unmapped, "mac", extractField(line, "MAC"))
	addUnmapped(event.Unmapped, "length", extractField(line, "LEN"))
	addUnmapped(event.Unmapped, "tos", extractField(line, "TOS"))
	addUnmapped(event.Unmapped, "ttl", extractField(line, "TTL"))
	addUnmapped(event.Unmapped, "id", eventID)

	// Preserve SSH-specific information when present.
	if strings.Contains(line, "sshd[") {
		addUnmapped(event.Unmapped, "service", "sshd")

		if user := sshUser(line); user != "" {
			addUnmapped(event.Unmapped, "user", user)
		}
	}

	// -----------------------------------------------------------------
	// 12. Add observables
	// -----------------------------------------------------------------

	if srcIP != "" {
		event.Observables = append(event.Observables, schema.Observable{
			Name:  "source_ip",
			Type:  "ip",
			Value: srcIP,
		})
	}

	if dstIP != "" {
		event.Observables = append(event.Observables, schema.Observable{
			Name:  "destination_ip",
			Type:  "ip",
			Value: dstIP,
		})
	}

	// -----------------------------------------------------------------
	// 13. Validate before returning
	// -----------------------------------------------------------------

	if err := event.Validate(); err != nil {
		return schema.Event{}, fmt.Errorf("Linux event validation failed: %w", err)
	}

	return event, nil
}

// activityForLinuxAction converts Linux actions to the OCSF activity IDs
// supported by the project's NetworkActivity class.
func activityForLinuxAction(action string) int {
	switch action {
	case "ALLOW", "ACCEPT":
		return schema.ActivityAllow

	case "BLOCK", "DROP", "FAIL", "NEW":
		// ActivityDetect is intentionally used here because NewEvent()
		// maps Detect to Deny for NetworkActivity.
		return schema.ActivityDetect

	default:
		return schema.ActivityUnknown
	}
}

// extractField extracts key=value fields such as:
//
//	SRC=192.168.1.20
//	DST=10.0.0.5
//	PROTO=TCP
//	SPT=12345
func extractField(line, key string) string {
	pattern := `(?:^|\s)` + regexp.QuoteMeta(key) + `=([^\s]+)`

	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(line)

	if len(match) < 2 {
		return ""
	}

	return strings.TrimSpace(match[1])
}

// parseIntField extracts an integer field such as SPT=12345.
func parseIntField(line, key string) int {
	value := extractField(line, key)

	if value == "" {
		return 0
	}

	n, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}

	if n < 0 || n > 65535 {
		return 0
	}

	return n
}

// protocolNumber returns the IANA protocol number for common protocols.
func protocolNumber(proto string) int {
	switch strings.ToUpper(proto) {
	case "TCP":
		return 6
	case "UDP":
		return 17
	case "ICMP":
		return 1
	case "ICMPV6":
		return 58
	default:
		return 0
	}
}

// linuxDirection determines the direction from IN=/OUT= fields.
func linuxDirection(line string) string {
	in := extractField(line, "IN")
	out := extractField(line, "OUT")

	switch {
	case in != "" && out == "":
		return "Inbound"

	case in == "" && out != "":
		return "Outbound"

	case in != "" && out != "":
		return "Bidirectional"

	default:
		return ""
	}
}

// linuxTimestamp extracts a traditional syslog timestamp:
//
//	Sep 11 12:00:01
//
// Syslog lines do not contain a year, so the current year is used.
func linuxTimestamp(line string) int64 {
	re := regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})`)

	match := re.FindStringSubmatch(line)

	if len(match) >= 2 {
		currentYear := time.Now().Year()

		value := fmt.Sprintf("%d %s", currentYear, match[1])

		t, err := time.ParseInLocation(
			"2006 Jan 2 15:04:05",
			value,
			time.Local,
		)

		if err == nil {
			return t.UnixMilli()
		}
	}

	// Some Linux audit messages contain an epoch timestamp.
	auditRE := regexp.MustCompile(`audit\((\d+)(?:\.\d+)?`)

	match = auditRE.FindStringSubmatch(line)

	if len(match) >= 2 {
		seconds, err := strconv.ParseInt(match[1], 10, 64)

		if err == nil {
			return seconds * 1000
		}
	}

	// If no timestamp exists, use current time.
	return schema.NowMillis()
}

// linuxHostname extracts the hostname from common Linux syslog formats.
func linuxHostname(line string) string {
	fields := strings.Fields(line)

	if len(fields) == 0 {
		return ""
	}

	// Traditional syslog:
	//
	// Sep 11 12:00:01 myhost sshd[1234]:
	if len(fields) >= 4 &&
		isMonth(fields[0]) {
		return fields[3]
	}

	// Sample lines such as:
	//
	// myhost kernel: ...
	//
	if len(fields) >= 2 {
		return strings.TrimSuffix(fields[0], ":")
	}

	return ""
}

// isMonth checks whether a string is a syslog month abbreviation.
func isMonth(value string) bool {
	switch value {
	case "Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec":
		return true
	default:
		return false
	}
}

// linuxMessage returns a useful human-readable message.
func linuxMessage(line string) string {
	switch {
	case strings.Contains(line, "[UFW BLOCK]"):
		return "Linux UFW blocked network traffic"

	case strings.Contains(line, "[UFW ALLOW]"):
		return "Linux UFW allowed network traffic"

	case strings.Contains(line, "[IPTABLES-DROP]"):
		return "Linux iptables dropped network traffic"

	case strings.Contains(line, "Failed password"):
		return "SSH authentication failed"

	case strings.Contains(line, "Accepted password"):
		return "SSH authentication succeeded"

	case strings.Contains(line, "[NEW SSH]"):
		return "New SSH connection"

	default:
		return "Linux network/security event"
	}
}

// sshUser extracts the username from SSH authentication messages.
func sshUser(line string) string {
	// Failed password for invalid user admin
	reInvalid := regexp.MustCompile(`Failed password for invalid user\s+(\S+)`)

	if match := reInvalid.FindStringSubmatch(line); len(match) >= 2 {
		return match[1]
	}

	// Failed password for zephex
	reFailed := regexp.MustCompile(`Failed password for\s+(\S+)`)

	if match := reFailed.FindStringSubmatch(line); len(match) >= 2 {
		return match[1]
	}

	// Accepted password for zephex
	reAccepted := regexp.MustCompile(`Accepted password for\s+(\S+)`)

	if match := reAccepted.FindStringSubmatch(line); len(match) >= 2 {
		return match[1]
	}

	return ""
}

// addUnmapped safely adds a value while respecting the project's
// maximum of 20 unmapped keys.
func addUnmapped(unmapped map[string]string, key, value string) {
	if value == "" {
		return
	}

	if _, exists := unmapped[key]; exists {
		return
	}

	if len(unmapped) >= 20 {
		return
	}

	unmapped[key] = value
}