package output

import (
	"context"
	"testing"

	"sih/src/parser"
	"sih/src/schema"
	"sih/utils"
)

func collectEvents(t *testing.T, lines []string) []schema.Event {
	t.Helper()
	var out []schema.Event
	for _, l := range lines {
		name := parser.DetectAll(l)
		if name == "" {
			t.Fatalf("no parser for line: %.80s", l)
		}
		p, _ := parser.Get(name)
		e, err := p.Parse(l)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		out = append(out, e)
	}
	return out
}

func TestSQLiteRoundTrip(t *testing.T) {
	ctx := context.Background()
	st, err := OpenSQLite(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	var lines []string
	lines = append(lines, utils.GenerateCiscoASA(50, 1)...)
	lines = append(lines, utils.GenerateFortiGate(50, 1)...)
	lines = append(lines, utils.GenerateSuricata(50, 1)...)
	lines = append(lines, utils.GenerateLinux(50, 1)...)
	events := collectEvents(t, lines)

	// Insert in two batches (exercises multi-transaction cursoring).
	if err := st.InsertBatch(ctx, events[:130]); err != nil {
		t.Fatalf("insert1: %v", err)
	}
	if err := st.InsertBatch(ctx, events[130:]); err != nil {
		t.Fatalf("insert2: %v", err)
	}

	n, err := st.Count(ctx)
	if err != nil || n != 200 {
		t.Fatalf("count=%d err=%v, want 200", n, err)
	}

	// Cursor pagination.
	page1, err := st.EventsSince(ctx, 0, 130)
	if err != nil || len(page1) != 130 {
		t.Fatalf("page1=%d err=%v", len(page1), err)
	}
	page2, err := st.EventsSince(ctx, page1[len(page1)-1].ID, 500)
	if err != nil || len(page2) != 70 {
		t.Fatalf("page2=%d err=%v", len(page2), err)
	}
	if page2[0].Event.RawDataHash != schema.HashRaw(page2[0].Event.RawData) {
		t.Fatal("raw hash mismatch after round-trip")
	}
	if err := page2[0].Event.Validate(); err != nil {
		t.Fatalf("round-trip validate: %v", err)
	}

	// Idempotent re-insert (kill-9 replay safety).
	if err := st.InsertBatch(ctx, events); err != nil {
		t.Fatalf("re-insert: %v", err)
	}
	n, _ = st.Count(ctx)
	if n != 200 {
		t.Fatalf("count after re-insert=%d, want 200 (INSERT OR IGNORE)", n)
	}
}

func TestRunWriterDrainsChannel(t *testing.T) {
	ctx := context.Background()
	st, err := OpenSQLite(t.TempDir() + "/w.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	hub := NewHub(16)

	ch := make(chan schema.Event, 10000)
	lines := utils.GenerateCiscoASA(1200, 3)
	events := collectEvents(t, lines)
	go func() {
		for _, e := range events {
			ch <- e
		}
		close(ch)
	}()
	if got := RunWriter(ctx, ch, st, hub); got != 1200 {
		t.Fatalf("inserted=%d, want 1200", got)
	}
	n, _ := st.Count(ctx)
	if n != 1200 {
		t.Fatalf("count=%d, want 1200", n)
	}
}
