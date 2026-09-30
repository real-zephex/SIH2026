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

// Regexes are compiled once at init. They previously lived inside the
// functions that use them, which meant a fresh compilation on every
// ParseLinux call (and three per call inside sshUser alone).
var (
	reLinuxSyslogTS  = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})`)
	reLinuxAuditTS   = regexp.MustCompile(`audit\((\d+)(?:\.\d+)?`)
	reSSHFailInvalid = regexp.MustCompile(`Failed password for invalid user\s+(\S+)`)
	reSSHFail        = regexp.MustCompile(`Failed password for\s+(\S+)`)
	reSSHAccept      = regexp.MustCompile(`Accepted password for\s+(\S+)`)
)

// monthLookup maps a 3-letter syslog month abbreviation to its time.Month.
// Used by the allocation-free fast path in linuxTimestamp.
var monthLookup = map[string]time.Month{
	"Jan": time.January, "Feb": time.February, "Mar": time.March,
	"Apr": time.April, "May": time.May, "Jun": time.June,
	"Jul": time.July, "Aug": time.August, "Sep": time.September,
	"Oct": time.October, "Nov": time.November, "Dec": time.December,
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
	//
	// IN/OUT are extracted once here and reused for both Direction and the
	// unmapped map below (previously each was scanned for twice).
	// -----------------------------------------------------------------

	ifaceIn := extractField(line, "IN")
	ifaceOut := extractField(line, "OUT")

	event.Direction = linuxDirectionFrom(ifaceIn, ifaceOut)

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

	// Sized for the common UFW/iptables case (8 keys) so the map does not
	// rehash while it is being populated.
	event.Unmapped = make(map[string]string, 8)

	addUnmapped(event.Unmapped, "hostname", linuxHostname(line))
	addUnmapped(event.Unmapped, "interface_in", ifaceIn)
	addUnmapped(event.Unmapped, "interface_out", ifaceOut)
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

	if srcIP != "" || dstIP != "" {
		event.Observables = make([]schema.Observable, 0, 2)
	}

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

	if err := event.ValidateNoRehash(); err != nil {
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
//
// Semantics match the original `(?:^|\s)KEY=([^\s]+)` regex: KEY must sit at
// the start of the line or after whitespace, and the value runs to the next
// whitespace. Implemented as a hand-rolled scan because this runs ~12x per
// line and the previous regexp.MustCompile-per-call cost dominated the parser
// (18.8 KB and ~130 us allocated per line).
//
// The returned string is a slice of line, so this allocates nothing.
func extractField(line, key string) string {
	n := len(key)
	if n == 0 {
		return ""
	}
	for i := 0; i+n < len(line); {
		j := strings.Index(line[i:], key)
		if j < 0 {
			return ""
		}
		p := i + j
		// key must be followed by '=' ...
		if p+n < len(line) && line[p+n] == '=' {
			// ... and preceded by start-of-line or whitespace.
			if p == 0 || isSpaceByte(line[p-1]) {
				vs := p + n + 1
				ve := vs
				for ve < len(line) && !isSpaceByte(line[ve]) {
					ve++
				}
				if ve > vs {
					return line[vs:ve]
				}
				return ""
			}
		}
		i = p + n
	}
	return ""
}

// isSpaceByte reports whether b is in the regexp \s class ([\t\n\f\r ]).
func isSpaceByte(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\f', '\r':
		return true
	}
	return false
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
	return linuxDirectionFrom(extractField(line, "IN"), extractField(line, "OUT"))
}

// linuxDirectionFrom is linuxDirection with the IN/OUT values already
// extracted by the caller, so the line is not rescanned for them.
func linuxDirectionFrom(in, out string) string {
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
//
// Fast path: "Mon DD HH:MM:SS" is parsed by hand, avoiding both the regex and
// time.Parse (the two dominant costs of this function). Falls back to the
// regex path for anything the fast path does not recognise, so behaviour is
// unchanged.
func linuxTimestamp(line string) int64 {
	if t, ok := parseSyslogTSFast(line); ok {
		return t
	}

	match := reLinuxSyslogTS.FindStringSubmatch(line)

	if len(match) >= 2 {
		currentYear := time.Now().Year()

		value := currentYearString(currentYear) + " " + match[1]

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
	match = reLinuxAuditTS.FindStringSubmatch(line)

	if len(match) >= 2 {
		seconds, err := strconv.ParseInt(match[1], 10, 64)

		if err == nil {
			return seconds * 1000
		}
	}

	// If no timestamp exists, use current time.
	return schema.NowMillis()
}

// currentYearString renders the year without fmt.Sprintf.
func currentYearString(y int) string {
	if y < 0 {
		return "-" + itoa(-y)
	}
	return itoa(y)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// parseSyslogTSFast hand-parses a leading "Mon DD HH:MM:SS" syslog stamp.
// Returns ok=false when the line does not start with a well-formed stamp, in
// which case the caller falls back to the regex path.
func parseSyslogTSFast(line string) (int64, bool) {
	// Shortest valid stamp: "Mon 1 0:00:00" = 12 bytes.
	if len(line) < 12 {
		return 0, false
	}
	mon, ok := monthLookup[line[0:3]]
	if !ok {
		return 0, false
	}
	i := 3
	// \s+
	sp := 0
	for i < len(line) && line[i] == ' ' {
		i++
		sp++
	}
	if sp == 0 {
		return 0, false
	}
	// \d{1,2}
	ds := i
	for i < len(line) && line[i] >= '0' && line[i] <= '9' && i-ds < 2 {
		i++
	}
	if i == ds {
		return 0, false
	}
	day, ok := atoi2(line[ds:i])
	if !ok {
		return 0, false
	}
	// \s+
	sp = 0
	for i < len(line) && line[i] == ' ' {
		i++
		sp++
	}
	if sp == 0 {
		return 0, false
	}
	// HH:MM:SS
	if i+8 > len(line) || line[i+2] != ':' || line[i+5] != ':' {
		return 0, false
	}
	hour, ok1 := atoi2(line[i : i+2])
	minute, ok2 := atoi2(line[i+3 : i+5])
	sec, ok3 := atoi2(line[i+6 : i+8])
	if !ok1 || !ok2 || !ok3 {
		return 0, false
	}
	if hour > 23 || minute > 59 || sec > 59 || day < 1 || day > 31 {
		return 0, false
	}
	return time.Date(time.Now().Year(), mon, day, hour, minute, sec, 0, time.Local).UnixMilli(), true
}

// atoi2 parses exactly the digits of s (len 1 or 2) without allocating.
func atoi2(s string) (int, bool) {
	if len(s) == 0 || len(s) > 2 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
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
// Uses the package-level precompiled regexes.
func sshUser(line string) string {
	// Failed password for invalid user admin
	if match := reSSHFailInvalid.FindStringSubmatch(line); len(match) >= 2 {
		return match[1]
	}

	// Failed password for zephex
	if match := reSSHFail.FindStringSubmatch(line); len(match) >= 2 {
		return match[1]
	}

	// Accepted password for zephex
	if match := reSSHAccept.FindStringSubmatch(line); len(match) >= 2 {
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
