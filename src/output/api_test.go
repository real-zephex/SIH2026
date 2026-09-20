package output

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sih/src/schema"
)

func testEvent(t *testing.T, action string) schema.Event {
	t.Helper()
	meta := schema.Metadata{
		Product:        schema.Product{Name: "ASA", Vendor: "Cisco", Version: "9.x"},
		Version:        schema.OCSFVersion,
		UID:            fmt.Sprintf("uid-%s-%d", action, time.Now().UnixNano()),
		CorrelationUID: "c",
	}
	e := schema.NewEvent(schema.ClassNetworkActivity, schema.ActivityAllow, schema.SeverityInfo, 1720000000000, meta, action)
	e.StatusID, e.Status = schema.StatusSuccess, "Success"
	e.SrcEndpoint = schema.Endpoint{IP: "10.0.0.1", Port: 1}
	e.DstEndpoint = schema.Endpoint{IP: "10.0.0.2", Port: 2}
	e.ProtocolName = "tcp"
	e.Action = action
	e.RawData = "raw-" + action
	e.RawDataHash = schema.HashRaw(e.RawData)
	e.RawDataSize = len(e.RawData)
	if err := e.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	return e
}

func TestHubLiveOnly(t *testing.T) {
	hub := NewHub(8)
	// Published BEFORE subscribe must NOT be received (live-from-connect).
	hub.Publish([]schema.Event{testEvent(t, "before")})
	ch := hub.Subscribe()
	defer hub.Unsubscribe(ch)
	hub.Publish([]schema.Event{testEvent(t, "after")})
	select {
	case ev := <-ch:
		if ev.Action != "after" {
			t.Fatalf("got pre-connect event: %s", ev.Action)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no live event received")
	}
	if hub.Subscribers() != 1 {
		t.Fatalf("subscribers=%d, want 1", hub.Subscribers())
	}
}

func TestHubSlowClientDropped(t *testing.T) {
	hub := NewHub(2)
	ch := hub.Subscribe()
	defer hub.Unsubscribe(ch)
	for i := 0; i < 10; i++ {
		hub.Publish([]schema.Event{testEvent(t, "x")})
	}
	if hub.Dropped == 0 {
		t.Fatal("expected slow-client drops, got 0")
	}
	_ = ch
}

func TestAPIEventsCursor(t *testing.T) {
	ctx := context.Background()
	st, _ := OpenSQLite(t.TempDir() + "/api.db")
	defer st.Close()
	hub := NewHub(8)
	var evs []schema.Event
	for _, a := range []string{"a", "b", "c"} {
		evs = append(evs, testEvent(t, a))
	}
	if err := st.InsertBatch(ctx, evs); err != nil {
		t.Fatalf("insert: %v", err)
	}
	srv := NewServer(st, hub, nil)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	get := func(q string) (int64, int) {
		resp, err := http.Get(ts.URL + q)
		if err != nil {
			t.Fatalf("get %s: %v", q, err)
		}
		defer resp.Body.Close()
		var body struct {
			Events      []schema.Event `json:"events"`
			NextSinceID int64          `json:"next_since_id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return body.NextSinceID, len(body.Events)
	}
	next, n := get("/api/events?limit=2")
	if n != 2 {
		t.Fatalf("page1=%d, want 2", n)
	}
	_, n = get(fmt.Sprintf("/api/events?since_id=%d&limit=10", next))
	if n != 1 {
		t.Fatalf("page2=%d, want 1", n)
	}
}

func TestStreamLiveOnly(t *testing.T) {
	ctx := context.Background()
	st, _ := OpenSQLite(t.TempDir() + "/sse.db")
	defer st.Close()
	hub := NewHub(8)
	srv := NewServer(st, hub, nil)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	hub.Publish([]schema.Event{testEvent(t, "pre")})

	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/stream", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("stream connect: %v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type=%q", ct)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	type result struct {
		data string
		err  error
	}
	got := make(chan result, 16)
	go func() {
		for sc.Scan() {
			if d := strings.TrimSpace(strings.TrimPrefix(sc.Text(), "data:")); strings.HasPrefix(sc.Text(), "data:") {
				got <- result{data: d}
				return
			}
		}
		got <- result{err: sc.Err()}
	}()
	time.Sleep(200 * time.Millisecond)
	hub.Publish([]schema.Event{testEvent(t, "live")})
	select {
	case r := <-got:
		if r.err != nil {
			t.Fatalf("scan: %v", r.err)
		}
		var ev schema.Event
		if err := json.Unmarshal([]byte(r.data), &ev); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if ev.Action != "live" {
			t.Fatalf("got action=%q, want live (pre-connect must not replay)", ev.Action)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no SSE event received")
	}
}
