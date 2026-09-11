package parser

import (
	"strings"
	"testing"

	"sih/src/schema"
	"sih/utils"
)

// TestDetectLinux checks that Linux firewall and SSH logs
// are correctly identified.
func TestDetectLinux(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		{
			name: "UFW BLOCK",
			line: "myhost kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.148.10.10 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=4444 DPT=22",
			want: true,
		},
		{
			name: "UFW ALLOW",
			line: "myhost kernel: [UFW ALLOW] IN=eth0 OUT= SRC=192.168.1.20 DST=172.18.0.1 LEN=52 PROTO=TCP SPT=54321 DPT=22",
			want: true,
		},
		{
			name: "IPTABLES DROP",
			line: "myhost kernel: [IPTABLES-DROP] IN=eth0 OUT= SRC=203.0.113.9 DST=172.18.0.5",
			want: true,
		},
		{
			name: "SSH failed password",
			line: "Sep 11 12:00:01 myhost sshd[1234]: Failed password for invalid user admin from 45.148.10.88 port 4444 ssh2",
			want: true,
		},
		{
			name: "SSH accepted password",
			line: "Sep 11 12:00:03 myhost sshd[1234]: Accepted password for zephex from 192.168.1.20 port 54321 ssh2",
			want: true,
		},
		{
			name: "Normal unrelated log",
			line: "myhost systemd: Started some service",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectLinux(tt.line)

			if got != tt.want {
				t.Errorf("DetectLinux() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestParseLinuxUFWBlock checks parsing of a UFW BLOCK event.
func TestParseLinuxUFWBlock(t *testing.T) {
	line := "myhost kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.148.10.10 DST=10.0.0.5 LEN=60 TOS=0x00 TTL=52 PROTO=TCP SPT=4444 DPT=22 ID=400001"

	event, err := ParseLinux(line)
	if err != nil {
		t.Fatalf("ParseLinux() returned error: %v", err)
	}

	// Check OCSF class.
	if event.ClassUID != schema.ClassNetworkActivity {
		t.Errorf(
			"ClassUID = %d, want %d",
			event.ClassUID,
			schema.ClassNetworkActivity,
		)
	}

	// BLOCK should become Deny through ActivityDetect.
	if event.ActivityID != schema.ActivityDeny {
		t.Errorf(
			"ActivityID = %d, want %d",
			event.ActivityID,
			schema.ActivityDeny,
		)
	}

	if event.SrcEndpoint.IP != "45.148.10.10" {
		t.Errorf(
			"SrcEndpoint.IP = %q, want %q",
			event.SrcEndpoint.IP,
			"45.148.10.10",
		)
	}

	if event.SrcEndpoint.Port != 4444 {
		t.Errorf(
			"SrcEndpoint.Port = %d, want %d",
			event.SrcEndpoint.Port,
			4444,
		)
	}

	if event.DstEndpoint.IP != "10.0.0.5" {
		t.Errorf(
			"DstEndpoint.IP = %q, want %q",
			event.DstEndpoint.IP,
			"10.0.0.5",
		)
	}

	if event.DstEndpoint.Port != 22 {
		t.Errorf(
			"DstEndpoint.Port = %d, want %d",
			event.DstEndpoint.Port,
			22,
		)
	}

	if event.ProtocolName != "TCP" {
		t.Errorf(
			"ProtocolName = %q, want %q",
			event.ProtocolName,
			"TCP",
		)
	}

	if event.ProtocolNum != 6 {
		t.Errorf(
			"ProtocolNum = %d, want %d",
			event.ProtocolNum,
			6,
		)
	}

	if event.Action != "BLOCK" {
		t.Errorf(
			"Action = %q, want %q",
			event.Action,
			"BLOCK",
		)
	}

	if event.RawData != line {
		t.Error("RawData does not match the original log line")
	}

	if event.RawDataHash != schema.HashRaw(line) {
		t.Error("RawDataHash does not match SHA-256 of RawData")
	}

	if event.RawDataSize != len(line) {
		t.Errorf(
			"RawDataSize = %d, want %d",
			event.RawDataSize,
			len(line),
		)
	}
}

// TestParseLinuxUFWAllow checks parsing of a UFW ALLOW event.
func TestParseLinuxUFWAllow(t *testing.T) {
	line := "myhost kernel: [UFW ALLOW] IN=eth0 OUT= SRC=192.168.1.20 DST=172.18.0.1 PROTO=TCP SPT=54321 DPT=22"

	event, err := ParseLinux(line)
	if err != nil {
		t.Fatalf("ParseLinux() returned error: %v", err)
	}

	if event.Action != "ALLOW" {
		t.Errorf(
			"Action = %q, want %q",
			event.Action,
			"ALLOW",
		)
	}

	if event.ActivityID != schema.ActivityAllow {
		t.Errorf(
			"ActivityID = %d, want %d",
			event.ActivityID,
			schema.ActivityAllow,
		)
	}

	if event.SrcEndpoint.IP != "192.168.1.20" {
		t.Errorf("source IP = %q", event.SrcEndpoint.IP)
	}

	if event.DstEndpoint.IP != "172.18.0.1" {
		t.Errorf("destination IP = %q", event.DstEndpoint.IP)
	}

	if event.ProtocolName != "TCP" {
		t.Errorf("protocol = %q, want TCP", event.ProtocolName)
	}
}

// TestParseLinuxIPTablesDrop checks IPTABLES-DROP parsing.
func TestParseLinuxIPTablesDrop(t *testing.T) {
	line := "myhost kernel: [IPTABLES-DROP] IN=eth0 OUT= SRC=203.0.113.9 DST=172.18.0.5 LEN=52 PROTO=UDP SPT=12345 DPT=53"

	event, err := ParseLinux(line)
	if err != nil {
		t.Fatalf("ParseLinux() returned error: %v", err)
	}

	if event.Action != "DROP" {
		t.Errorf(
			"Action = %q, want %q",
			event.Action,
			"DROP",
		)
	}

	if event.SrcEndpoint.IP != "203.0.113.9" {
		t.Errorf("source IP = %q", event.SrcEndpoint.IP)
	}

	if event.DstEndpoint.IP != "172.18.0.5" {
		t.Errorf("destination IP = %q", event.DstEndpoint.IP)
	}

	if event.ProtocolName != "UDP" {
		t.Errorf(
			"ProtocolName = %q, want UDP",
			event.ProtocolName,
		)
	}

	if event.ProtocolNum != 17 {
		t.Errorf(
			"ProtocolNum = %d, want 17",
			event.ProtocolNum,
		)
	}
}

// TestParseLinuxSSHFailed checks SSH failed-login parsing.
func TestParseLinuxSSHFailed(t *testing.T) {
	line := "Sep 11 12:00:01 myhost sshd[1234]: Failed password for invalid user admin from 45.148.10.88 port 4444 ssh2"

	event, err := ParseLinux(line)
	if err != nil {
		t.Fatalf("ParseLinux() returned error: %v", err)
	}

	if event.Action != "FAIL" {
		t.Errorf(
			"Action = %q, want %q",
			event.Action,
			"FAIL",
		)
	}

	if event.Message != "SSH authentication failed" {
		t.Errorf(
			"Message = %q, want %q",
			event.Message,
			"SSH authentication failed",
		)
	}

	if event.Unmapped["service"] != "sshd" {
		t.Errorf(
			"service = %q, want sshd",
			event.Unmapped["service"],
		)
	}

	if event.Unmapped["user"] != "admin" {
		t.Errorf(
			"user = %q, want admin",
			event.Unmapped["user"],
		)
	}

	if event.Unmapped["service"] != "sshd" {
		t.Errorf("SSH service was not stored in unmapped")
	}

	if !strings.Contains(event.RawData, "Failed password") {
		t.Error("original SSH message was not preserved")
	}

	if err := event.Validate(); err != nil {
		t.Fatalf("event.Validate() failed: %v", err)
	}
}

// TestParseLinuxSSHAccepted checks SSH successful-login parsing.
func TestParseLinuxSSHAccepted(t *testing.T) {
	line := "Sep 11 12:00:03 myhost sshd[1234]: Accepted password for zephex from 192.168.1.20 port 54321 ssh2"

	event, err := ParseLinux(line)
	if err != nil {
		t.Fatalf("ParseLinux() returned error: %v", err)
	}

	if event.Action != "ACCEPT" {
		t.Errorf(
			"Action = %q, want %q",
			event.Action,
			"ACCEPT",
		)
	}

	if event.ActivityID != schema.ActivityAllow {
		t.Errorf(
			"ActivityID = %d, want %d",
			event.ActivityID,
			schema.ActivityAllow,
		)
	}

	if event.Message != "SSH authentication succeeded" {
		t.Errorf(
			"Message = %q, want %q",
			event.Message,
			"SSH authentication succeeded",
		)
	}

	if event.Unmapped["user"] != "zephex" {
		t.Errorf(
			"user = %q, want zephex",
			event.Unmapped["user"],
		)
	}

	if err := event.Validate(); err != nil {
		t.Fatalf("event.Validate() failed: %v", err)
	}
}

// TestParseLinuxRawDataIntegrity checks the lossless requirement.
func TestParseLinuxRawDataIntegrity(t *testing.T) {
	line := "myhost kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.148.10.10 DST=10.0.0.5 PROTO=TCP SPT=4444 DPT=22"

	event, err := ParseLinux(line)
	if err != nil {
		t.Fatalf("ParseLinux() returned error: %v", err)
	}

	if event.RawData != line {
		t.Errorf("RawData was changed")
	}

	expectedHash := schema.HashRaw(line)

	if event.RawDataHash != expectedHash {
		t.Errorf(
			"RawDataHash = %q, want %q",
			event.RawDataHash,
			expectedHash,
		)
	}

	if event.RawDataSize != len(line) {
		t.Errorf(
			"RawDataSize = %d, want %d",
			event.RawDataSize,
			len(line),
		)
	}
}

// TestParseLinuxEmpty checks that an empty log is rejected.
func TestParseLinuxEmpty(t *testing.T) {
	_, err := ParseLinux("")

	if err == nil {
		t.Error("ParseLinux() expected an error for empty input")
	}
}

// TestParseLinuxValidation checks that every successfully parsed
// event passes the canonical schema validation.
func TestParseLinuxValidation(t *testing.T) {
	lines := []string{
		"myhost kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.148.10.10 DST=10.0.0.5 PROTO=TCP SPT=4444 DPT=22",

		"myhost kernel: [UFW ALLOW] IN=eth0 OUT= SRC=192.168.1.20 DST=172.18.0.1 PROTO=TCP SPT=54321 DPT=22",

		"myhost kernel: [IPTABLES-DROP] IN=eth0 OUT= SRC=203.0.113.9 DST=172.18.0.5 PROTO=UDP SPT=12345 DPT=53",

		"Sep 11 12:00:01 myhost sshd[1234]: Failed password for invalid user admin from 45.148.10.88 port 4444 ssh2",

		"Sep 11 12:00:03 myhost sshd[1234]: Accepted password for zephex from 192.168.1.20 port 54321 ssh2",
	}

	for _, line := range lines {
		event, err := ParseLinux(line)

		if err != nil {
			t.Fatalf(
				"ParseLinux() failed for %q: %v",
				line,
				err,
			)
		}

		if err := event.Validate(); err != nil {
			t.Fatalf(
				"event.Validate() failed for %q: %v",
				line,
				err,
			)
		}
	}
}

// TestParseLinuxSynthetic round-trips the utils.GenerateLinux bulk generator:
// every synthetic line must Detect, Parse, Validate, and preserve raw_data.
func TestParseLinuxSynthetic(t *testing.T) {
	lines := utils.GenerateLinux(10000, 42)

	// if len(lines) != 200 {
	// 	t.Fatalf(
	// 		"generated %d lines, want 200",
	// 		len(lines),
	// 	)
	// }

	count := 0

	seen := map[string]int{}

	for i, line := range lines {
		if !DetectLinux(line) {
			t.Fatalf(
				"synthetic line %d: DetectLinux returned false\nraw: %.160s",
				i+1,
				line,
			)
		}

		event, err := ParseLinux(line)

		if err != nil {
			t.Fatalf(
				"synthetic line %d: ParseLinux failed: %v\nraw: %.160s",
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

		seen[event.Action]++
		count++
	}

	t.Logf("Processed %d log lines", count)

	// Generator must cover the parser's action space, not just one shape.
	for _, want := range []string{"BLOCK", "ALLOW", "DROP", "FAIL", "ACCEPT", "NEW"} {
		if seen[want] == 0 {
			t.Fatalf(
				"synthetic set has no %s events (got %v)",
				want,
				seen,
			)
		}
	}
}
