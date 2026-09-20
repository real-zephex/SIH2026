# ULPF — Universal Log Pre-processing Framework

> **Smart India Hackathon 2026 | Problem Statement #25165**
> Team **Syntax Error** — Go + SQLite + Next.js

---

## Overview

Security analysts waste days writing custom parsers for every new network device before their SIEM can use its logs — during which that device is a blind spot.

**ULPF** is a universal log pre-processing framework that ingests heterogeneous perimeter device logs (Cisco ASA, FortiGate, Suricata, Linux iptables/UFW/sshd), normalizes them to a lossless OCSF-Slim v1.8 schema, stores in SQLite WAL, and serves via REST API + SSE for live SIEM integration.

New vendor? One small mapping. Nothing downstream changes.

---

## Architecture

```
FileTail / TickerFeed / SynthFeed (per vendor)
        │
   FanIn (merges all sources into one Line channel)
        │
   Pool (NumCPU workers)
   ├─ DetectAll  (sniff vendor)
   ├─ Parse      (vendor-specific → schema.Event)
   └─ Validate   (OCSF required fields)
        │
   buffered chan Event [cap 10k]
   ├─ spill-to-disk on backpressure (never silent drop)
   │
   dbWriter (sole SQLite writer)
   ├─ batch 500 / 100ms flush
   ├─ INSERT OR IGNORE on event_id (idempotent restart)
   │
   ┌───────────┴───────────┐
   │                       │
 SQLite WAL          Hub (live broadcast)
   │                       │
 /api/events         /stream (SSE)
 (cursor pull)       (live push)
```

---

## Supported Sources

| Source | Parser | Method | Sample Lines |
|--------|--------|--------|--------------|
| Cisco ASA | `src/parser/cisco_asa.go` | Syslog regex (302013/14/15/16, 106100, 725001) | 20 |
| FortiGate | `src/parser/fortigate.go` | CEF `logid`-keyed structured parse | 20 |
| Suricata | `src/parser/suricata.go` | EVE JSON direct decode | 30 |
| Linux | `src/parser/linux.go` | Regex + stateful pairing (iptables/UFW/sshd) | 20 |

Each parser outputs the same `schema.Event` — OCSF-Slim v1.8 compliant:
- `type_uid = class_uid × 100 + activity_id`
- `raw_data` preserved byte-for-byte
- `raw_data_hash` (sha256) for integrity verification
- `unmapped` field for vendor-specific extras

---

## Output & Integration

### SQLite (primary store)
- WAL mode, single writer, air-gap safe
- File doubles as Data Lake seed
- `INSERT OR IGNORE` for idempotent restarts

### REST API
| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /api/events?since_id=N&limit=100&source=cisco` | Cursor-paginated events |
| `GET /stats` | Pipeline stats (parsed/db_rows/failed/chan_depth/spill) |

### SSE (Server-Sent Events)
| Endpoint | Description |
|----------|-------------|
| `GET /stream` | Live event push, 15s heartbeat, slow-client dropped |

### Legacy SIEM Adapters (15 lines each)
- `ToCEF()` — ArcSight / FortiSIEM
- `ToLEEF()` — IBM QRadar
- `ToECS()` — Elastic

---

## Project Structure

```
SIH2026/
├── src/
│   ├── parser/                  # Vendor parsers
│   │   ├── parser.go            # Parser interface + DetectAll registry
│   │   ├── adapters.go          # FortiGate/Linux struct adapters
│   │   ├── cisco_asa.go         # Cisco ASA
│   │   ├── fortigate.go         # FortiGate
│   │   ├── suricata.go          # Suricata EVE
│   │   └── linux.go             # Linux iptables/UFW/sshd
│   ├── schema/
│   │   └── event.go             # OCSF-Slim v1.8 Event + NewEvent/Validate/HashRaw/adapters
│   ├── pipeline/
│   │   ├── config.go            # ChanCap=10k, SpillTimeout=2s, SynthEvery=2s, SynthBatch=25
│   │   ├── ingest.go            # Feed interface, FileTail, TickerFeed, SynthFeed, FanIn
│   │   └── pool.go              # NumCPU workers, Stats, spill-to-disk
│   └── output/
│       ├── db.go                # SQLiteStore, RunWriter (batch 500/100ms)
│       ├── hub.go               # Live-only pub/sub for SSE
│       └── api.go               # /api/events, /stream, /health, /stats
├── utils/
│   ├── feature.go               # Shared utilities
│   ├── synth_asa.go             # Cisco ASA synthetic generator
│   ├── synth_fortigate.go       # FortiGate synthetic generator
│   ├── synth_suricata.go        # Suricata synthetic generator
│   └── synth_linux.go           # Linux synthetic generator
├── samples/                     # Validated sample logs per vendor
│   ├── cisco_asa.log
│   ├── fortigate.log
│   ├── suricata_eve.json
│   ├── linux_iptables.log
│   ├── paloalto_csv.log
│   └── paloalto_leef.log
├── main.go                      # Daemon entry point (Feed → Pool → Store → SSE)
├── go.mod                       # go 1.27 — modernc.org/sqlite (pure-Go, CGO_ENABLED=0)
├── Dockerfile                   # Multi-stage, distroless, air-gap ready
├── API.md                       # Full API contract with TypeScript examples
├── REQS.md                      # Ingestion source requirements
└── MARK1.md                     # Build plan
```

---

## Quick Start

### Prerequisites
- Go 1.27+

### Run

```bash
go build -o ulpf .
./ulpf
```

Or directly:

```bash
go run .
```

### Run Tests

```bash
go test ./...
go test -race ./...
```

### Test a Single Parser

```bash
go test ./src/parser/ -run TestParseCiscoASA
go test ./src/parser/ -run TestParseFortiGate
go test ./src/parser/ -run TestParseSuricata
go test ./src/parser/ -run TestParseLinux
```

---

## API Examples

```bash
# Health check
curl http://localhost:8080/health

# Get last 10 events
curl http://localhost:8080/api/events?limit=10

# Filter by source
curl http://localhost:8080/api/events?source=cisco_asa&limit=5

# Resume from cursor (no dupes, no loss)
curl http://localhost:8080/api/events?since_id=1000&limit=100

# Pipeline stats
curl http://localhost:8080/stats

# Live SSE stream (Ctrl+C to stop)
curl -N http://localhost:8080/stream
```

---

## Verified Numbers

| Metric | Value |
|--------|-------|
| Curated test lines | 90 routed (88/90 by design) |
| Synthetic soak | 8,000 (2,000/source), zero failures |
| Cisco 100k soak | 100,000 lines, zero failures |
| Sustained EPS | ~50 on laptop |
| Channel capacity | 10,000 events buffered |
| Batch flush | 500 rows / 100ms |
| New source onboarding | ~30–60 min (proven 4×) |
| Legacy adapter size | ~15 lines each (CEF/LEEF/ECS) |

---

## How to Add a New Source

1. **Detect** — add a sniff rule in `src/parser/parser.go:DetectAll()` (~5 lines)
2. **Parse** — write `func ParseXxx(raw string) (*schema.Event, error)` (~100–300 lines)
3. **Register** — call `Register("xxx", ParseXxx)` in an `init()` (~1 line)

Pool, channel, batch writer, database, API, SSE, and dashboard work unchanged.

Proven: Cisco → FortiGate → Suricata → Linux, each onboarded in hours.

---

## Air-Gap Deployment

- `CGO_ENABLED=0` — no C compiler needed
- `modernc.org/sqlite` — pure-Go SQLite, vendored in `go.sum`
- No cloud APIs, no LLM calls in the core pipeline
- Single static binary + SQLite file = full deployment
- `Dockerfile` included (multi-stage → distroless)

---

## Dashboard (sih2026-webapp)

Separate Next.js app (bun, shadcn, framer-motion, recharts):

- **Topology view** — source nodes → engine → DB + SSE sinks with animated packet flow
- **Live feed** — memoized rows, 4Hz batch flush, pause/resume, event detail sheet with raw data + sha256
- **Charts** — EPS area graph + severity bar chart
- **Keyboard shortcuts** — `/` search, `esc` clear, `space` pause
- **Deep link** — `?source=cisco_asa` filters to one vendor

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Go 1.27 |
| Database | SQLite (WAL mode, pure-Go via `modernc.org/sqlite`) |
| API | Go `net/http` (REST + SSE) |
| Dashboard | Next.js, shadcn/ui, framer-motion, recharts |
| Schema | OCSF-Slim v1.8 |
| CI | `go vet`, `go test -race`, `gofmt` |

---

## License

Built for Smart India Hackathon 2026. See problem statement #25165.
