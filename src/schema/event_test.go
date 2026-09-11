package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

func testMeta() Metadata {
	return Metadata{
		Product:        Product{Name: "ASA", Vendor: "Cisco", Version: "9.17"},
		Version:        OCSFVersion,
		UID:            "11111111-2222-3333-4444-555555555555",
		CorrelationUID: "11111111-2222-3333-4444-555555555555",
	}
}

func TestTypeUIDArithmetic(t *testing.T) {
	if got := TypeUIDFor(4001, 1); got != 400101 {
		t.Fatalf("want 400101 got %d", got)
	}
	if got := TypeUIDFor(2004, 1); got != 200401 {
		t.Fatalf("want 200401 got %d", got)
	}
}

func TestNetworkActivityValid(t *testing.T) {
	raw := "%ASA-6-302013: Built outbound TCP connection 76118 for outside:207.68.178.45/80 to inside:192.168.20.31/3530"
	e := NewEvent(ClassNetworkActivity, ActivityAllow, SeverityInfo, 1720000000000, testMeta(), "Built outbound TCP")
	e.StatusID, e.Status = StatusSuccess, "Success"
	e.SrcEndpoint = Endpoint{IP: "192.168.20.31", Port: 3530}
	e.DstEndpoint = Endpoint{IP: "207.68.178.45", Port: 80}
	e.ProtocolName = "tcp"
	e.Direction = "outbound"
	e.Action = "Built"
	e.RawData = raw
	e.RawDataHash = HashRaw(raw)
	e.RawDataSize = len(raw)
	if err := e.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if e.CategoryUID != CategoryNetwork || e.TypeUID != 400101 {
		t.Fatalf("bad category/type: %+v", e)
	}
	b, _ := json.Marshal(e)
	if !strings.Contains(string(b), `"class_uid":4001`) {
		t.Fatalf("missing class_uid in json: %s", b)
	}
}

func TestDetectionFindingDetectMapsToCreate(t *testing.T) {
	e := NewEvent(ClassDetectionFinding, ActivityDetect, SeverityHigh, 1720000000000, testMeta(), "ET SCAN")
	if e.ActivityID != ActivityCreate || e.TypeUID != 200401 {
		t.Fatalf("detect must map to create/200401, got %+v", e)
	}
}

func TestValidateRejects(t *testing.T) {
	e := NewEvent(ClassNetworkActivity, ActivityAllow, SeverityInfo, 1720000000000, testMeta(), "x")
	e.RawData = "abc"
	e.RawDataHash = "wrong"
	if err := e.Validate(); err == nil {
		t.Fatal("expected hash mismatch error")
	}
	e2 := NewEvent(9999, 1, 1, 1, testMeta(), "x")
	if err := e2.Validate(); err == nil {
		t.Fatal("expected class error")
	}
}

func TestAdapters(t *testing.T) {
	raw := "x"
	e := NewEvent(ClassNetworkActivity, ActivityDeny, SeverityMedium, 1720000000000, testMeta(), "Deny")
	e.SrcEndpoint = Endpoint{IP: "10.0.0.1", Port: 1}
	e.DstEndpoint = Endpoint{IP: "10.0.0.2", Port: 2}
	e.ProtocolName = "tcp"
	e.Action = "Deny"
	e.RawData = raw
	e.RawDataHash = HashRaw(raw)
	ecs := e.ToECS()
	if ecs["source.ip"] != "10.0.0.1" || ecs["destination.ip"] != "10.0.0.2" {
		t.Fatalf("bad ecs map: %v", ecs)
	}
	if !strings.HasPrefix(e.ToCEF(), "CEF:0|Cisco|ASA|") {
		t.Fatalf("bad cef: %s", e.ToCEF())
	}
	if !strings.HasPrefix(e.ToLEEF(), "LEEF:2.0|Cisco|ASA|") {
		t.Fatalf("bad leef: %s", e.ToLEEF())
	}
}
