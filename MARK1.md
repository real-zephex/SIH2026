# ULPF MARK1 — Universal Log Pre-processing Framework (SIH 25165)

> One-page-for-each-teammate detailed build plan. Stack: Go 1.27. Team: 4 tech + 2 presentation. Time: 12h.
> Deliverables: source link + README setup + arch doc (2pp) + demo video (2min) + 5 slides.

## 1. What we are building

A single Go binary + SQLite file + HTTP API that converts **any perimeter network device log**
into one lossless, SIEM-ready JSON stream.

```
[file tail / syslog TCP] -> per-source goroutine -> Detect + Parse
  -> Normalize (OCSF-Slim) -> buffered chan NormalizedEvent{cap 10k}
  -> single dbWriter (batch 500) -> SQLite-WAL (events table)
  -> GET /api/events?since_id&limit (SIEM pull) + GET /stream SSE (dashboard/live)
  -> normalized.jsonl (Data Lake + ML-ready)
```

Guarantees (maps to PS `ps.md:21-40`):

- a) lossless: store `raw` + `raw_hash=sha256(raw)` on every row.
- b/c) parse + normalize into common taxonomy (OCSF-Slim, Sec 3).
- d) traceability: `event_id=uuid` + `rowid` cursor, `unmapped{}` keeps leftover vendor fields.
- e) plug-and-play: `src/registry.RegisterParser(name, Detect, Parse)` — new source = 1 file + 1 line.
- f/g) unified view: one table, one API, one dashboard regardless of vendor.
- h) ML-ready: normalized numeric/categorical features (Sec 5).
- j/k) air-gapped + container: stdlib + SQLite + `Dockerfile`, no cloud calls in core.

## 2. Why Go (goroutines + channels)

- One goroutine per input source tails/reads concurrently; a parser worker pool
  (`NumCPU` workers) parses concurrently. Throughput scales with cores, no threads to manage.
- All parsers push to **one buffered channel**. Buffer absorbs bursts; DB slowness never
  blocks parsing until buffer fills (then we spill to disk + count, never silent-drop).
- **One `dbWriter` goroutine** drains the channel and batch-writes SQLite. This avoids
  multi-writer lock contention (SQLite writes are sequential by design).
- SIEM speed is not our problem after commit: SIEM pulls with its own cursor
  (`since_id`). Slow SIEM = lagging cursor, fast path (dashboard) unaffected.
- Placement per `AGENTS.md`: features in `src/`, shared helpers in `utils/`.

```
src/schema/event.go        OCSF-Slim struct + Validate()
src/registry/registry.go   RegisterParser, Detect, dispatch
src/ingest/file.go         file tail (now); src/ingest/syslog.go (later, same iface)
src/parser/asa.go          Cisco ASA syslog
src/parser/fortigate.go    FortiGate syslog/CEF
src/parser/suricata.go     Suricata EVE JSON
src/parser/paloalto.go     PAN-OS CSV + LEEF/CEF
src/parser/linux.go        iptables/UFW fallback
src/pipeline/worker.go     pools, chan(10k), context cancel, drop/disk-spill counters
src/normalize/normalize.go vendor -> OCSF mapping + time/IP/enum canon
src/output/db.go           SQLite-WAL writer, schema, retention rotate
src/output/api.go          /api/events, /stream SSE, /health, /stats
src/detect/stats.go        L1 z-score/rate/entropy (pure Go, gonum/stat only)
utils/hash.go utils/time.go utils/ip.go
ml/anomaly.py              L2 IsolationForest sidecar (offline, optional)
samples/*                  98 lines curated + raw_downloads/ (see samples/README.md)
```

## 3. Output schema: OCSF-Slim v1.8 (do NOT invent)

Primary output is OCSF JSON (backed by Splunk+AWS+IBM+Elastic). Covers perimeter needs:
`4001 NetworkActivity, 4002 HTTP, 4003 DNS, 2004 DetectionFinding` (Suricata alerts).
Full OCSF is 100+ fields — we implement ~25 (Slim) in `src/schema/event.go`:

```go
type Endpoint struct { IP string `json:"ip"`; Port int `json:"port"` }
type Event struct {
  ClassUID int `json:"class_uid"`; ClassName string `json:"class_name"`
  Category string `json:"category_name"`; ActivityID int `json:"activity_id"`
  Time int64 `json:"time"`; SeverityID int `json:"severity_id"`
  Status, Action, Message, Protocol, Direction string
  SrcEndpoint, DstEndpoint Endpoint; Packets, Bytes int64
  Metadata struct{ Product, Vendor, Version string }
  Raw string `json:"raw_data"`; RawHash string `json:"raw_data_hash"`
  EventID string `json:"event_id"`; Unmapped map[string]string `json:"unmapped"`
}
```

Canon rules: `time` = ms UTC (RFC3339Nano in JSON), IPs trimmed/lowercased, `proto` =
`tcp/udp/icmp`, `action` keeps vendor verb (`Built/Deny/Alert`) + `activity_id` normalizes
(1 allow, 2 deny, 6 detect). Adapters (30 lines each): `ToCEF() ToLEEF() ToECS()`
e.g. `src_endpoint.ip -> source.ip`. Demo on Elastic? emit ECS alias. QRadar? emit LEEF.

## 4. Ingestion sources: 4 (3 must + 1 stretch)

| # | Source | Format | Owner | Sample file |
|---|---|---|---|---|
| 1 | Cisco ASA firewall | unstructured Syslog | Dev1 | `samples/cisco_asa.log` (20) |
| 2 | FortiGate firewall | Syslog/CEF kv | Dev2 | `samples/fortigate.log` (20) |
| 3 | Suricata IDS EVE | JSON | Dev3 | `samples/suricata_eve.json` (30) |
| 4 | Palo Alto PAN-OS | CSV + LEEF/CEF (stretch) | Dev4 | `paloalto_csv.log` (3) + `paloalto_leef.log` (5) |
| 5 | Linux iptables/UFW | netfilter (fallback demo) | shared | `samples/linux_iptables.log` (20) |

Why these: two firewall vendors = vendor-agnostic proof; IDS = threat-hunt story;
together they hit all PS format families (Syslog, CEF, LEEF, JSON). 2 sources looks
trivial, 5+ will not finish. Bulk origins in `samples/README.md`
(elastic/integrations, Suricata wrccdc-2018, IBM QRadar LEEF docs, `journalctl -k`).

Parser contract: `Detect(line string) bool` (cheap prefix sniff: `%ASA-`, `logid=`,
`LEEF:`, `"event_type"`) then `Parse(line) (Event, error)`. 20 sample lines each is
enough to green-test.

## 5. ML: 7/10 demo, 3/10 prod (secondary by design)

PS asks ML-**ready**, not a live model. Do not put LLM APIs in core (breaks air-gap).

- L1 must (pure Go, 2h, 1 dev): per-IP rolling stats with `gonum/stat` —
  event rate, fail ratio, distinct ports, byte mean/std, hour entropy; flag `z>3`.
  No deps, works offline, satisfies h).
- L2 wow (parallel, 3h): `ml/anomaly.py` — `sklearn IsolationForest(contamination=0.1)`
  on `[count, fail_ratio, distinct_ports, bytes_mean, hour_std, iat_mean]` per IP,
  reads `normalized.jsonl`, writes `anomalies.jsonl{event_id,score,severity}`.
  Pre-train, vendor `model.pkl`, demo offline. Demo line:
  "rules caught brute-force, ML caught port-scan with no signature".
- L3 do-not-attempt live: deep nets, streaming training, billions/day tuning.

## 6. DB + API (slow-consumer fix)

- `events(id INTEGER PK, event_id TEXT UNIQUE, class_uid INT, time INT, src_ip, dst_ip,
  src_port, dst_port, proto, action, severity, raw TEXT, raw_hash TEXT, ocsf_json TEXT)`.
- WAL mode, batch 500, single writer; retention rotate (e.g. keep 1M rows) so disk never fills.
- `GET /api/events?since_id=<rowid>&limit=500 -> {events[], next_since_id}`.
  `GET /stream` SSE live tail. `GET /health /stats{eps, per_source, dropped}`.
- Dashboard: Go `net/http` templates + SSE (no React, 1h, air-gap safe). Shows inputs,
  EPS, live table, per-source counts.

## 7. 12-hour runbook

- 0–2h (all): freeze `src/schema + registry + chan + dbWriter` skeleton; `go vet/test` green.
- 2–7h (parallel): Dev1–4 build 4 parsers against `samples/`; L1 detect + dashboard skeleton in parallel.
- 7–10h: integrate, `normalized.jsonl` + SQLite + API + SSE; `gofmt -w . && go vet ./... && go test ./...`; `Dockerfile`.
- 10–12h: freeze code; Pres team cuts 2-min video, 5 slides, arch 2-pager, README setup.
- Pres team owns throughout: samples curation, docs, slides, demo script, threshold tuning.

## 8. Done criteria (demo must show)

1. `cat samples/*.log | ./ulpf` -> same `src_ip,dst_ip,action,proto` query works across all 4.
2. Every row shows `raw` + `raw_hash` + `event_id` (lossless/traceable).
3. Kill -9 mid-stream, restart, SIEM resumes from `since_id` with no dup/loss.
4. Unplug network (air-gap) — pipeline + dashboard still run; `docker build/run` works.
5. New source demo: drop `samples/new.log` + register parser (1 file) without restarting core.
