package output

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"sih/src/pipeline"
)

// Server serves the Next.js / SIEM contract off a Store + Hub.
type Server struct {
	Store Store
	Hub   *Hub
	Pool  *pipeline.Pool // nil-safe; /stats includes pool counters when set
	mux   *http.ServeMux
}

// NewServer builds the routes (no HTML dashboard — Next.js consumes these).
func NewServer(store Store, hub *Hub, pool *pipeline.Pool) *Server {
	s := &Server{Store: store, Hub: hub, Pool: pool, mux: http.NewServeMux()}
	s.mux.HandleFunc("/api/events", s.handleEvents)
	s.mux.HandleFunc("/stream", s.handleStream)
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/stats", s.handleStats)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// handleEvents: GET /api/events?since_id=<rowid>&limit=<n>
// Cursor pagination for SIEMs and the Next.js history view.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since_id"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, err := s.Store.EventsSince(r.Context(), since, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	events := make([]any, 0, len(rows))
	var next int64 = since
	for _, row := range rows {
		events = append(events, row.Event)
		next = row.ID
	}
	writeJSON(w, map[string]any{"events": events, "next_since_id": next})
}

// handleStream: GET /stream — SSE live tail of committed events.
//
// Semantics (locked): streams events committed AFTER connect; no replay.
// Clients needing history fetch /api/events first, then attach here.
// 15s heartbeat comments keep proxies from killing idle streams.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := s.Hub.Subscribe()
	defer s.Hub.Unsubscribe(ch)
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	fmt.Fprintf(w, ": connected\n\n")
	fl.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			js, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: ulpf\ndata: %s\n\n", js)
			fl.Flush()
		case <-heartbeat.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			fl.Flush()
		}
	}
}

// handleHealth: GET /health — liveness for containers/orchestrators.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"status": "ok", "time": time.Now().UTC().Format(time.RFC3339)})
}

// handleStats: GET /stats — pipeline counters + store + hub numbers.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"hub_subscribers": s.Hub.Subscribers(),
		"hub_dropped":     s.Hub.Dropped,
	}
	if s.Pool != nil {
		for k, v := range s.Pool.Stats.Snapshot(len(s.Pool.Out)) {
			out[k] = v
		}
	}
	if n, err := s.Store.Count(context.Background()); err == nil {
		out["db_rows"] = n
	}
	writeJSON(w, out)
}
