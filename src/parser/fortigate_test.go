package parser

import (
	"bufio"
	"os"
	"testing"

	"sih/src/schema"
)

func TestFortiGateGolden20(t *testing.T) {
	f, err := os.Open("../../samples/fortigate.log")
	if err != nil {
		t.Fatalf("open FortiGate samples: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	lineNo := 0
	parsed := 0

	for scanner.Scan() {
		lineNo++
		line := scanner.Text()

		if !Detect(line) {
			t.Fatalf(
				"line %d: Detect returned false",
				lineNo,
			)
		}

		event, err := Parse(line)
		if err != nil {
			t.Fatalf(
				"line %d: Parse failed: %v\nraw: %s",
				lineNo,
				err,
				line,
			)
		}

		if err := event.Validate(); err != nil {
			t.Fatalf(
				"line %d: Validate failed: %v",
				lineNo,
				err,
			)
		}

		// Lossless raw preservation.
		if event.RawData != line {
			t.Fatalf(
				"line %d: raw_data was not preserved",
				lineNo,
			)
		}

		if event.RawDataHash == "" {
			t.Fatalf(
				"line %d: raw_data_hash is empty",
				lineNo,
			)
		}

		if event.RawDataSize != len(line) {
			t.Fatalf(
				"line %d: raw_data_size=%d, want %d",
				lineNo,
				event.RawDataSize,
				len(line),
			)
		}

		if event.Metadata.UID == "" {
			t.Fatalf(
				"line %d: metadata.uid is empty",
				lineNo,
			)
		}

		parsed++
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf(
			"read FortiGate samples: %v",
			err,
		)
	}

	if parsed != 20 {
		t.Fatalf(
			"parsed %d samples, want 20",
			parsed,
		)
	}
}

func TestFortiGateLine1(t *testing.T) {
	f, err := os.Open("../../samples/fortigate.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	if !scanner.Scan() {
		t.Fatal("could not read line 1")
	}

	event, err := Parse(scanner.Text())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if event.SrcEndpoint.IP != "10.1.100.22" {
		t.Errorf(
			"source IP = %q, want %q",
			event.SrcEndpoint.IP,
			"10.1.100.22",
		)
	}

	if event.DstEndpoint.IP != "67.43.156.14" {
		t.Errorf(
			"destination IP = %q, want %q",
			event.DstEndpoint.IP,
			"67.43.156.14",
		)
	}

	if event.DstEndpoint.Port != 443 {
		t.Errorf(
			"destination port = %d, want 443",
			event.DstEndpoint.Port,
		)
	}

	if event.ProtocolName != "tcp" {
		t.Errorf(
			"protocol = %q, want tcp",
			event.ProtocolName,
		)
	}

	if event.ProtocolNum != 6 {
		t.Errorf(
			"protocol number = %d, want 6",
			event.ProtocolNum,
		)
	}

	if event.Action != "pass" {
		t.Errorf(
			"action = %q, want pass",
			event.Action,
		)
	}

	if event.ClassUID != schema.ClassNetworkActivity {
		t.Errorf(
			"class_uid = %d, want %d",
			event.ClassUID,
			schema.ClassNetworkActivity,
		)
	}
}

func TestFortiGateUTMFinding(t *testing.T) {
	f, err := os.Open("../../samples/fortigate.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	// Read lines 1-4.
	for i := 0; i < 4; i++ {
		if !scanner.Scan() {
			t.Fatalf(
				"could not read sample line %d",
				i+1,
			)
		}
	}

	event, err := Parse(scanner.Text())
	if err != nil {
		t.Fatalf("Parse line 4: %v", err)
	}

	if event.ClassUID != schema.ClassDetectionFinding {
		t.Fatalf(
			"line 4 class_uid = %d, want %d",
			event.ClassUID,
			schema.ClassDetectionFinding,
		)
	}

	if event.ActivityID != schema.ActivityCreate {
		t.Fatalf(
			"line 4 activity_id = %d, want %d",
			event.ActivityID,
			schema.ActivityCreate,
		)
	}

	if event.FindingInfo != "EICAR-Test-Signature" {
		t.Errorf(
			"finding_info = %q, want EICAR-Test-Signature",
			event.FindingInfo,
		)
	}
}

func TestFortiGateSystemEventWithoutIP(t *testing.T) {
	f, err := os.Open("../../samples/fortigate.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	// Line 6 is the system event with no srcip/dstip.
	for i := 0; i < 6; i++ {
		if !scanner.Scan() {
			t.Fatalf(
				"could not read sample line %d",
				i+1,
			)
		}
	}

	line := scanner.Text()

	if !Detect(line) {
		t.Fatal(
			"line 6 should be detected as FortiGate",
		)
	}

	event, err := Parse(line)
	if err != nil {
		t.Fatalf(
			"Parse line 6: %v",
			err,
		)
	}

	if event.SrcEndpoint.IP != "" {
		t.Errorf(
			"line 6 source IP = %q, want empty",
			event.SrcEndpoint.IP,
		)
	}

	if event.DstEndpoint.IP != "" {
		t.Errorf(
			"line 6 destination IP = %q, want empty",
			event.DstEndpoint.IP,
		)
	}

	if event.Message != "Interface port9 link up" {
		t.Errorf(
			"line 6 message = %q, want %q",
			event.Message,
			"Interface port9 link up",
		)
	}
}

func TestTokenizeFortiGateQuotedValues(t *testing.T) {
	line := `logid="123" type="utm" msg="Web.Client: HTTPS.BROWSER," app="HTTPS.BROWSER"`

	kv := tokenizeKV(line)

	if kv["logid"] != "123" {
		t.Errorf(
			"logid = %q, want 123",
			kv["logid"],
		)
	}

	if kv["type"] != "utm" {
		t.Errorf(
			"type = %q, want utm",
			kv["type"],
		)
	}

	if kv["msg"] != "Web.Client: HTTPS.BROWSER," {
		t.Errorf(
			"msg = %q, want %q",
			kv["msg"],
			"Web.Client: HTTPS.BROWSER,",
		)
	}

	if kv["app"] != "HTTPS.BROWSER" {
		t.Errorf(
			"app = %q, want HTTPS.BROWSER",
			kv["app"],
		)
	}
}
