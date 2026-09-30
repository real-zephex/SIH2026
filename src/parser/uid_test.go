package parser

import (
	"regexp"
	"sync"
	"testing"
)

// uuidV4Shape is the RFC 4122 layout newUID must produce.
var uuidV4Shape = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// TestNewUIDShape guards the trace-id format. The event UID is the dedup key
// written to SQLite, so a malformed value silently corrupts event_id
// traceability. This specifically catches a class of bug where a separator
// index is advanced without the separator byte being written, which yields
// embedded NUL bytes and a truncated tail.
func TestNewUIDShape(t *testing.T) {
	for i := 0; i < 2000; i++ {
		uid := newUID()
		if len(uid) != 36 {
			t.Fatalf("uid %q has length %d, want 36", uid, len(uid))
		}
		if !uuidV4Shape.MatchString(uid) {
			t.Fatalf("uid %q does not match RFC 4122 v4 shape", uid)
		}
		for j := 0; j < len(uid); j++ {
			if uid[j] == 0 {
				t.Fatalf("uid %q contains a NUL byte at %d", uid, j)
			}
		}
	}
}

// TestNewUIDUnique checks uniqueness under concurrency: the counter-based
// construction must not collide even when many workers generate IDs at once.
func TestNewUIDUnique(t *testing.T) {
	const workers, each = 16, 2000

	var mu sync.Mutex
	seen := make(map[string]struct{}, workers*each)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]string, 0, each)
			for i := 0; i < each; i++ {
				local = append(local, newUID())
			}
			mu.Lock()
			for _, u := range local {
				seen[u] = struct{}{}
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(seen) != workers*each {
		t.Fatalf("got %d unique uids, want %d (collision)", len(seen), workers*each)
	}
}
