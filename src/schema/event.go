// Package schema defines the ULPF canonical output event.
//
// OCSF-Slim v1.8: exact OCSF field names/types for all REQUIRED + RECOMMENDED
// base-event attributes, plus the two event classes we emit:
//   - 4001 NetworkActivity (category 4) for ASA / FortiGate / PAN-OS traffic / Linux
//   - 2004 DetectionFinding (category 2) for Suricata / PAN-OS threat
//
// Compliance rule: required fields must always be populated; recommended should
// be; optional OCSF objects are omitted (still valid). PS-required lossless fields
// map to OCSF native: raw -> raw_data, sha256 -> raw_data_hash, trace id ->
// metadata.uid + metadata.correlation_uid (see EventID helper).
package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// OCSF schema version we target.
const OCSFVersion = "1.8.0"

// Category UIDs (OCSF taxonomy).
const (
	CategoryFindings = 2
	CategoryNetwork  = 4
)

// Class UIDs we emit.
const (
	ClassNetworkActivity  = 4001
	ClassDetectionFinding = 2004
)

// Activity IDs (per-class semantics documented on NewEvent callers):
// Network 4001: 1 Allow, 2 Deny, 0 Unknown. Finding 2004: 1 Create, 0 Unknown.
// 6 Detect is our cross-class alias used pre-normalization; NewEvent maps it to
// the class-appropriate value (4001->2 Deny w/ detect note, 2004->1 Create).
const (
	ActivityUnknown = 0
	ActivityAllow   = 1
	ActivityDeny    = 2
	ActivityCreate  = 1
	ActivityDetect  = 6
)

// Severity IDs (OCSF): 0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical.
const (
	SeverityUnknown = 0
	SeverityInfo    = 1
	SeverityLow     = 2
	SeverityMedium  = 3
	SeverityHigh    = 4
	SeverityFatal   = 5
)

// Status IDs: 0 Unknown, 1 Success, 2 Failure, 99 Other.
const (
	StatusUnknown = 0
	StatusSuccess = 1
	StatusFailure = 2
	StatusOther   = 99
)

// Product identifies the observed vendor product (OCSF product object, slim).
type Product struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor,omitempty"`
	Version string `json:"version,omitempty"`
}

// Metadata is the OCSF required metadata object (slim).
type Metadata struct {
	Product        Product `json:"product"`
	Version        string  `json:"version"` // OCSF schema version, e.g. 1.8.0
	UID            string  `json:"uid"`     // == EventID (traceability, PS d)
	CorrelationUID string  `json:"correlation_uid,omitempty"`
}

// Endpoint is the OCSF endpoint object (slim: ip + port only).
type Endpoint struct {
	IP   string `json:"ip,omitempty"`
	Port int    `json:"port,omitempty"`
}

// Traffic holds byte/packet counters (OCSF traffic object, slim).
type Traffic struct {
	Packets int64 `json:"packets,omitempty"`
	Bytes   int64 `json:"bytes,omitempty"`
}

// Observable is an OCSF observable entry (slim).
type Observable struct {
	Name  string `json:"name"`
	Type  string `json:"type,omitempty"`
	Value string `json:"value"`
}

// Event is the canonical ULPF output. JSON keys match OCSF exactly so output
// validates with ocsf-toolkit and ingests into Splunk/AWS/QRadar/Elastic.
type Event struct {
	// Classification (required).
	ClassUID     int    `json:"class_uid"`
	ClassName    string `json:"class_name,omitempty"`
	CategoryUID  int    `json:"category_uid"`
	CategoryName string `json:"category_name,omitempty"`
	ActivityID   int    `json:"activity_id"`
	ActivityName string `json:"activity_name,omitempty"`
	TypeUID      int64  `json:"type_uid"`
	TypeName     string `json:"type_name,omitempty"`
	SeverityID   int    `json:"severity_id"`
	Severity     string `json:"severity,omitempty"`
	StatusID     int    `json:"status_id,omitempty"`
	Status       string `json:"status,omitempty"`
	Message      string `json:"message,omitempty"`

	// Occurrence (required: time).
	Time int64 `json:"time"` // ms since epoch (OCSF timestamp_t)

	// Context (required: metadata; optional but PS-mandated: raw_*).
	Metadata    Metadata          `json:"metadata"`
	RawData     string            `json:"raw_data,omitempty"`
	RawDataHash string            `json:"raw_data_hash,omitempty"`
	RawDataSize int               `json:"raw_data_size,omitempty"`
	Observables []Observable      `json:"observables,omitempty"`
	Unmapped    map[string]string `json:"unmapped,omitempty"`

	// Network class attributes (populated for 4001; src/dst reused for 2004).
	SrcEndpoint  Endpoint `json:"src_endpoint,omitempty"`
	DstEndpoint  Endpoint `json:"dst_endpoint,omitempty"`
	ProtocolName string   `json:"protocol_name,omitempty"`
	ProtocolNum  int      `json:"protocol_num,omitempty"`
	Direction    string   `json:"direction,omitempty"`
	Action       string   `json:"action,omitempty"`
	Traffic      Traffic  `json:"traffic,omitempty"`

	// Finding class attributes (2004 only).
	FindingInfo string `json:"finding_info,omitempty"`
	Confidence  string `json:"confidence,omitempty"`
}

// TypeUIDFor computes OCSF type_uid = class_uid*100 + activity_id.
func TypeUIDFor(classUID, activityID int) int64 {
	return int64(classUID*100 + activityID)
}

// ClassNameFor returns the display name for classes we emit.
func ClassNameFor(classUID int) string {
	switch classUID {
	case ClassNetworkActivity:
		return "Network Activity"
	case ClassDetectionFinding:
		return "Detection Finding"
	default:
		return "Unknown"
	}
}

// CategoryForClass returns the category for classes we emit.
func CategoryForClass(classUID int) (uid int, name string) {
	switch classUID {
	case ClassNetworkActivity:
		return CategoryNetwork, "Network Activity"
	case ClassDetectionFinding:
		return CategoryFindings, "Findings"
	default:
		return 0, "Uncategorized"
	}
}

// EventID returns the trace id (metadata.uid).
func (e Event) EventID() string { return e.Metadata.UID }

// TimeRFC3339 renders Time as UTC RFC3339Nano (for ECS @timestamp / display).
func (e Event) TimeRFC3339() string {
	return time.UnixMilli(e.Time).UTC().Format(time.RFC3339Nano)
}

// NewEvent builds a valid Event, computing TypeUID/TypeName/Category and
// raw_data_size. activityDetect (6) is mapped per class: 4001->Deny, 2004->Create.
func NewEvent(classUID, activityID, severityID int, tsMillis int64, meta Metadata, msg string) Event {
	act := activityID
	actName := ""
	switch classUID {
	case ClassNetworkActivity:
		switch act {
		case ActivityAllow:
			actName = "Allow"
		case ActivityDeny:
			actName = "Deny"
		case ActivityDetect:
			act, actName = ActivityDeny, "Deny"
		default:
			act, actName = ActivityUnknown, "Unknown"
		}
	case ClassDetectionFinding:
		if act == ActivityDetect {
			act = ActivityCreate
		}
		switch act {
		case ActivityCreate:
			actName = "Create"
		default:
			act, actName = ActivityUnknown, "Unknown"
		}
	}
	catUID, catName := CategoryForClass(classUID)
	className := ClassNameFor(classUID)
	tuid := TypeUIDFor(classUID, act)
	return Event{
		ClassUID:     classUID,
		ClassName:    className,
		CategoryUID:  catUID,
		CategoryName: catName,
		ActivityID:   act,
		ActivityName: actName,
		TypeUID:      tuid,
		TypeName:     fmt.Sprintf("%s: %s", className, actName),
		SeverityID:   severityID,
		Severity:     SeverityName(severityID),
		Time:         tsMillis,
		Metadata:     meta,
		Message:      msg,
	}
}

// SeverityName maps severity_id to caption.
func SeverityName(id int) string {
	switch id {
	case SeverityInfo:
		return "Informational"
	case SeverityLow:
		return "Low"
	case SeverityMedium:
		return "Medium"
	case SeverityHigh:
		return "High"
	case SeverityFatal:
		return "Critical"
	default:
		return "Unknown"
	}
}

// HashRaw returns hex sha256 of raw (for raw_data_hash).
func HashRaw(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// NowMillis returns current time as OCSF ms epoch.
func NowMillis() int64 { return time.Now().UTC().UnixMilli() }

// Validate checks OCSF required-field compliance + PS lossless fields.
func (e Event) Validate() error {
	if e.ClassUID != ClassNetworkActivity && e.ClassUID != ClassDetectionFinding {
		return fmt.Errorf("class_uid must be 4001 or 2004, got %d", e.ClassUID)
	}
	catWant, _ := CategoryForClass(e.ClassUID)
	if e.CategoryUID != catWant {
		return fmt.Errorf("category_uid must be %d for class %d, got %d", catWant, e.ClassUID, e.CategoryUID)
	}
	if want := TypeUIDFor(e.ClassUID, e.ActivityID); e.TypeUID != want {
		return fmt.Errorf("type_uid must be class*100+activity (%d), got %d", want, e.TypeUID)
	}
	if e.SeverityID < 0 || e.SeverityID > 5 {
		return fmt.Errorf("severity_id out of range 0-5: %d", e.SeverityID)
	}
	if e.Time <= 0 {
		return fmt.Errorf("time must be positive ms epoch")
	}
	if e.Metadata.Product.Name == "" || e.Metadata.Version == "" || e.Metadata.UID == "" {
		return fmt.Errorf("metadata.product.name, metadata.version, metadata.uid are required")
	}
	if e.RawData == "" {
		return fmt.Errorf("raw_data is required (PS lossless)")
	}
	if e.RawDataHash != HashRaw(e.RawData) {
		return fmt.Errorf("raw_data_hash must be sha256(raw_data)")
	}
	for _, ep := range []Endpoint{e.SrcEndpoint, e.DstEndpoint} {
		if ep.IP != "" && net.ParseIP(ep.IP) == nil {
			return fmt.Errorf("invalid ip %q", ep.IP)
		}
		if ep.Port < 0 || ep.Port > 65535 {
			return fmt.Errorf("port out of range: %d", ep.Port)
		}
	}
	if len(e.Unmapped) > 20 {
		return fmt.Errorf("unmapped capped at 20 keys, got %d", len(e.Unmapped))
	}
	return nil
}

// --- SIEM adapters (DB/file is primary; Elastic live only if extra time) ---

// ToECS returns the Elastic alias view: OCSF -> ECS field renames.
func (e Event) ToECS() map[string]any {
	return map[string]any{
		"@timestamp":       e.TimeRFC3339(),
		"ecs.version":      "8.17.0",
		"event.kind":       "event",
		"event.category":   []string{strings.ToLower(e.CategoryName)},
		"event.type":       []string{strings.ToLower(e.ActivityName)},
		"source.ip":        e.SrcEndpoint.IP,
		"source.port":      e.SrcEndpoint.Port,
		"destination.ip":   e.DstEndpoint.IP,
		"destination.port": e.DstEndpoint.Port,
		"network.protocol": e.ProtocolName,
		"event.action":     e.Action,
		"message":          e.Message,
		"event.original":   e.RawData,
		"labels.event_id":  e.EventID(),
	}
}

// ToCEF renders a CEF:0 wire line for legacy SIEMs.
func (e Event) ToCEF() string {
	// CEF:Version|Vendor|Product|Ver|Signature|Name|Sev|extensions
	ext := url.Values{}
	ext.Set("src", e.SrcEndpoint.IP)
	ext.Set("dst", e.DstEndpoint.IP)
	ext.Set("spt", fmt.Sprint(e.SrcEndpoint.Port))
	ext.Set("dpt", fmt.Sprint(e.DstEndpoint.Port))
	ext.Set("proto", e.ProtocolName)
	ext.Set("act", e.Action)
	ext.Set("msg", e.Message)
	ext.Set("cs1", e.EventID())
	ext.Set("cs1Label", "event_id")
	// url.Values encodes with & separators; CEF uses space-separated k=v — replace.
	return fmt.Sprintf("CEF:0|%s|%s|%s|%d|%s|%d|%s",
		e.Metadata.Product.Vendor, e.Metadata.Product.Name,
		e.Metadata.Product.Version, e.TypeUID, e.TypeName,
		e.SeverityID, strings.ReplaceAll(ext.Encode(), "&", " "))
}

// ToLEEF renders a LEEF:2.0 wire line for QRadar-style SIEMs.
func (e Event) ToLEEF() string {
	p := e.Metadata.Product
	attrs := fmt.Sprintf("cat=%s\tsrc=%s\tdst=%s\tsrcPort=%d\tdstPort=%d\tproto=%s\taction=%s\tsev=%d\tmsg=%s\teventID=%s",
		e.CategoryName, e.SrcEndpoint.IP, e.DstEndpoint.IP,
		e.SrcEndpoint.Port, e.DstEndpoint.Port, e.ProtocolName,
		e.Action, e.SeverityID, e.Message, e.EventID())
	return fmt.Sprintf("LEEF:2.0|%s|%s|%s|%d|\t%s",
		p.Vendor, p.Name, p.Version, e.TypeUID, attrs)
}
