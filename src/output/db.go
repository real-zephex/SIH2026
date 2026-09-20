// Package output persists normalized events and serves them.
//
// Store is the persistence contract (SQLiteStore implements it; swap DB by
// implementing Store). dbWriter (RunWriter) is the SOLE drainer of the
// pipeline channel: batch insert, then publish to the Hub.
package output

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"sih/src/schema"
)

// Locked Phase-2 tunables (hardcoded consts per team decision).
const (
	// BatchSize rows per SQLite transaction.
	BatchSize = 500
	// FlushInterval bounds trickle latency when traffic is sparse.
	FlushInterval = 100 * time.Millisecond
	// RetentionRows caps the table (delete-oldest rotation).
	RetentionRows = 1000000
)

// Row is one stored event with its cursor.
type Row struct {
	ID    int64
	Event schema.Event
}

// Store persists and queries events.
type Store interface {
	InsertBatch(ctx context.Context, events []schema.Event) error
	EventsSince(ctx context.Context, sinceID int64, limit int) ([]Row, error)
	Count(ctx context.Context) (int64, error)
	Rotate(ctx context.Context) error
	Close() error
}

// SQLiteStore is the WAL-mode SQLite Store implementation.
type SQLiteStore struct {
	db *sql.DB
}

// OpenSQLite opens (creating) path with WAL mode and the events schema.
func OpenSQLite(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	for _, pragma := range []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA synchronous=NORMAL;`,
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, err
		}
	}
	s := &SQLiteStore{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQLiteStore) migrate() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		event_id TEXT NOT NULL UNIQUE,
		class_uid INTEGER NOT NULL,
		time_ms INTEGER NOT NULL,
		src_ip TEXT NOT NULL DEFAULT '',
		dst_ip TEXT NOT NULL DEFAULT '',
		src_port INTEGER NOT NULL DEFAULT 0,
		dst_port INTEGER NOT NULL DEFAULT 0,
		proto TEXT NOT NULL DEFAULT '',
		action TEXT NOT NULL DEFAULT '',
		severity INTEGER NOT NULL DEFAULT 0,
		raw TEXT NOT NULL,
		raw_hash TEXT NOT NULL,
		ocsf_json TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_events_time ON events(time_ms);
	CREATE INDEX IF NOT EXISTS idx_events_src ON events(src_ip);`)
	return err
}

// InsertBatch writes events in one transaction (INSERT OR IGNORE keeps
// restarts idempotent on event_id).
func (s *SQLiteStore) InsertBatch(ctx context.Context, events []schema.Event) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO events
		(event_id, class_uid, time_ms, src_ip, dst_ip, src_port, dst_port, proto, action, severity, raw, raw_hash, ocsf_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range events {
		js, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if _, err := stmt.ExecContext(ctx, e.EventID(), e.ClassUID, e.Time,
			e.SrcEndpoint.IP, e.DstEndpoint.IP, e.SrcEndpoint.Port, e.DstEndpoint.Port,
			e.ProtocolName, e.Action, e.SeverityID, e.RawData, e.RawDataHash, string(js)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// EventsSince returns rows with id > sinceID (cursor pagination for SIEMs).
func (s *SQLiteStore) EventsSince(ctx context.Context, sinceID int64, limit int) ([]Row, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, ocsf_json FROM events WHERE id > ? ORDER BY id ASC LIMIT ?`, sinceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Row
	for rows.Next() {
		var r Row
		var js string
		if err := rows.Scan(&r.ID, &js); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(js), &r.Event); err != nil {
			return nil, fmt.Errorf("corrupt row %d: %w", r.ID, err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Count returns total rows.
func (s *SQLiteStore) Count(ctx context.Context) (int64, error) {
	var n int64
	return n, s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&n)
}

// Rotate deletes oldest rows beyond RetentionRows.
func (s *SQLiteStore) Rotate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE id <= (SELECT MAX(id) FROM events) - ?`, RetentionRows)
	return err
}

// Close closes the DB.
func (s *SQLiteStore) Close() error { return s.db.Close() }

// RunWriter drains ch (sole receiver), batch-inserts, publishes to hub.
// Batches flush at BatchSize or FlushInterval. Returns when ch closes.
func RunWriter(ctx context.Context, ch <-chan schema.Event, store Store, hub *Hub) (inserted int64) {
	batch := make([]schema.Event, 0, BatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := store.InsertBatch(ctx, batch); err == nil {
			inserted += int64(len(batch))
			hub.Publish(batch)
		}
		batch = batch[:0]
	}
	timer := time.NewTimer(FlushInterval)
	defer timer.Stop()
	defer flush()
	for {
		select {
		case <-ctx.Done():
			return inserted
		case ev, ok := <-ch:
			if !ok {
				return inserted
			}
			batch = append(batch, ev)
			if len(batch) >= BatchSize {
				flush()
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(FlushInterval)
			}
		case <-timer.C:
			flush()
			timer.Reset(FlushInterval)
		}
	}
}
