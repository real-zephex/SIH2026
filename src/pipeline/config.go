// Package pipeline wires feeds -> parser pool -> output channel.
//
// Locked tunables live here as hardcoded constants (per team decision;
// a flags-based config comes later). Only main.go wires this package to
// src/output; pipeline never imports output.
package pipeline

import "time"

// Locked Phase-2 tunables.
const (
	// ChanCap bounds the parsed-event channel (burst headroom, ~20MB worst case).
	ChanCap = 10000
	// SpillTimeout bounds how long a worker waits on a full channel before
	// spilling the event to disk (never silent loss).
	SpillTimeout = 2 * time.Second
	// FilePollInterval for FileTail append detection.
	FilePollInterval = 200 * time.Millisecond
	// SynthEvery paces the continuous background feed (TickerFeed default).
	SynthEvery = 2 * time.Second
	// SynthBatch lines per tick per source (4 sources x 25 = ~50 EPS).
	SynthBatch = 25
)
