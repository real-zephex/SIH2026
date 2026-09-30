# ULPF — Project Walkthrough Video Plan

**Deliverable:** `brag.mp4` · 1920×1080 · 30fps · **4:28 (268s)**
**Format:** landscape
**Tone:** `polished` — serious, technical, confident. Restraint over spectacle.
**Supersedes:** the 21s launch cut in `brag-output-2026-09-30-154900/`. That one is
the shareable teaser; this one is the walkthrough a judge or a teammate actually watches.

**Every number, log line, and code snippet in this video is real.** Nothing is
illustrative. All figures come from `PERF_REPORT.md` (measured on an AMD Ryzen 5
7430U, 6C/12T, Go 1.27) or from source in this repo. All raw log lines are verbatim
from `samples/`. All code excerpts are copied from the files named on screen.

---

## 0. Honesty constraint (governs the whole edit)

`main` contains the parsers and the schema. It does **not** contain the pipeline,
the SQLite store, the REST/SSE API, or the Dockerfile — those live on
`feature/phase2-pipeline`, which is unmerged. `main.go` on `main` is `Hello World`.

This is not a footnote; `PERF_REPORT.md` §7 already flags it as a **P0** defect:
*"Fix the README — it documents a pipeline, SQLite, API/SSE and dashboard that are
not on `main`. A judge who clones `main` will not find them."*

**Therefore Scene 8 is a dedicated, un-skippable honesty beat.** The video shows the
full architecture, then tells the viewer exactly which branch it lives on and which
part is merged. The alternative — narrating an architecture that isn't in the
default branch — would be the single most damaging thing this video could do, since
its entire credibility rests on the measured numbers later in Act 3.

Verified current state:

| Check | Result |
|---|---|
| `go build ./...` | clean |
| `go vet ./...` | clean |
| `go test ./...` | `ok sih/src/parser`, `ok sih/src/schema` |
| Merged LOC (Go, excl. tests) | 3,777 across 12 files |
| Test LOC | 1,403 |
| Vendors parsing to one schema | 4 |

---

## 1. Deep context & milestones

### The problem solved

Perimeter devices emit mutually incompatible logs. A SIEM cannot ingest them until
someone writes a vendor-specific parser — typically a week of regex work per device
model. During that week the device is a network blind spot. The parser backlog *is*
the vulnerability.

### Architecture, in one line

`Feeds → FanIn → NumCPU worker pool (Detect→Parse→Validate) → 10k buffered channel → single SQLite writer (batch 500/100ms) → {WAL store, SSE Hub}`

### Architectural breakthroughs worth naming on camera

1. **The 3-method parser contract.** `Name() / Detect() / Parse()` at
   `src/parser/parser.go:17`. Onboarding a vendor touches nothing downstream.
   Proven four times: Cisco → FortiGate → Suricata → Linux.
2. **Losslessness as a verifiable property, not a promise.** Every event carries
   `raw_data` byte-for-byte plus `raw_data_hash` (sha256). You recompute it; you
   don't take our word.
3. **Backpressure instead of silent drops.** `pool.go:handle()` — a full channel
   makes a worker wait 2s, then spill to disk and increment a counter. A saturating
   pipeline is *visible*, not lossy.
4. **Deterministic detection.** `DetectAll` walks an ordered `[]Parser` slice, not a
   Go map. Map iteration order is randomized by design; in a security pipeline, which
   parser wins must not vary run to run.

### Measurable outcomes (all measured, `PERF_REPORT.md`)

| Metric | Value |
|---|---|
| Ingest ceiling (parser pool, 12 workers) | 537,900 events/s |
| End-to-end incl. SQLite writer | 16,700 rows/s |
| Store alone, isolated | 35,740 rows/s |
| Linux parser | 38,485 → 511 ns/line (**75×**) |
| Bytes allocated per event | 5,682 → 441 B (**12.9×**) |
| Allocations per event | 56.4 → 4.01 (**14×**) |
| End-to-end from a 5.1× parser speedup | **+9.5%** (the honest twist) |
| Silent event loss found by measurement | **2.8%** |

The last two are the most valuable things in this project, and both are *negative*
results reported without spin. Act 3 is built around them.

### Git milestones

`feature/cisco` → `feature/fortigate` → `feature/suricata` → `feature/linux` (all
merged via PRs #1–#4) → `093f64c unified all parsers` → `d353735 docs` →
`feature/phase2-pipeline` (pipeline, store, API, Dockerfile — **unmerged**).

---

## 2. Timestamped script & scene breakdown

**Total: 4:28.** Scene durations sum exactly to 268s.

### ACT 0 — HOOK & PROBLEM · 0:00–0:32 (32s)

#### Scene 1 — Four languages · 0:00–0:07 (7s)
- **Visual:** Black. Four real raw lines arrive from four directions, each with a
  vendor chip. They land at staggered x-offsets and never align. Hairline grid
  behind. One scanline sweep on entry.
  - `Cisco ASA` — `Oct 10 2018 12:34:56 localhost CiscoASA[999]: %ASA-6-305011: Built dynamic TCP translation from inside:172.31.98.44/1772 to outside:192.168.98.44/8256`
  - `FortiGate` — `<190>date=2019-05-15 time=18:03:37 logid="0000000013" type="traffic" srcip=10.1.100.22 dstip=8.8.8.8 srcport=50799 dstport=53 proto=17 action="accept"`
  - `Suricata` — `{"timestamp": "2018-03-24T14:37:19.037299-0600", "event_type": "alert", "src_ip": "0.0.0.0", "dest_ip": "10.47.8.150", "dest_port": 22, "alert": {"signature": "ET SCAN Potential SSH Scan", "severity": 2}}`
  - `Linux` — `myhost kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.148.10.88 DST=10.0.0.5 PROTO=TCP SPT=4444 DPT=22`
- **On-screen text:** `Four perimeter devices. Four log formats.` → `Zero of them agree.`
- **Narration:** "Every firewall, IDS, and host on your network speaks its own
  dialect. Cisco ASA emits syslog prose. FortiGate emits key-equals-value. Suricata
  emits nested JSON. Linux netfilter emits key-value soup. Four of them, sitting
  right next to each other, and not one of them can talk to the others."
- **B-Roll / text:** vendor chips only. No motion beyond entry.
- **Audio intent:** dry, tense. Low pulse under silence.
- **Audio-coupled:** four lines land in sequence on four separate ticks.
- **Transition:** hard dip to near-black → Scene 2.

#### Scene 2 — The tax · 0:07–0:16 (9s)
- **Visual:** The four lines compress into an unreadable wall on the left third.
  Right side: a cost stack builds line by line —
  `1 new device model` → `1 new parser` → `~1 week`. Then a red rule, then:
  `Until then: a blind spot.`
- **On-screen text:** `New device → new parser → a week of regex.`
- **Narration:** "So the SIEM stays dark. And the fix — a hand-written regex parser
  per vendor — is roughly a week of work per device model. Which means for that week,
  the device is a blind spot."
- **B-Roll / text:** counter ticks `0 → 1` on "new device model".
- **Audio intent:** the weight lands. Sub hit on the red rule.
- **Audio-coupled:** cost stack reveals one row per beat.
- **Transition:** wall slides left, diagram area opens → Scene 3.

#### Scene 3 — The blind spot · 0:16–0:23 (7s)
- **Visual:** Minimal network graph: four source nodes, one SIEM sink. Packets flow
  from three nodes into the sink. The fourth node pulses red, `UNPARSED`, and no
  packets ever leave it. Counter beneath the sink: `0 events from node 4`.
- **On-screen text:** `0 events reach the SIEM.`
- **Narration:** "That's the real cost. Not the parser you haven't written yet —
  the attacks you're not seeing because of it."
- **B-Roll / text:** red node label + zero counter. Nothing else.
- **Audio intent:** uncomfortable. The music thins to almost nothing.
- **Audio-coupled:** red node pulses on the beat; packets visibly route around it.
- **Transition:** graph collapses inward to a single point → Scene 4.

#### Scene 4 — Title / promise · 0:23–0:32 (9s)
- **Visual:** The point becomes the four lines snapping into one aligned vertical
  stack — the convergence. Wordmark resolves.
  **ULPF** / `Universal Log Pre-processing Framework` / `One schema. Nothing lost.`
  / `SIH 2026 · PS #25165 · CACHE ME OUTSIDE`
- **Narration:** "ULPF. Universal Log Pre-processing Framework. Four formats in,
  one schema out, nothing lost — and a hash so you can prove it."
- **B-Roll / text:** the four vendor chips merge into one `OCSF-Slim v1.8` chip.
- **Audio intent:** release. First full pad statement, resolving.
- **Audio-coupled:** wordmark lands on a strong cue. // beat-locked
- **Transition:** stack scales down into the pipeline diagram → Scene 5.

### ACT 1 — SYSTEM ARCHITECTURE & TECH STACK · 0:32–1:20 (48s)

#### Scene 5 — The pipeline · 0:32–0:46 (14s)
- **Visual:** The full dataflow diagram builds left→right, one stage at a time, with
  packets animating through as each stage lights.
  `FileTail / TickerFeed / SynthFeed` → `FanIn` → `Pool · NumCPU workers` →
  `{ DetectAll → Parse → Validate }` → `chan Event · cap 10,000` →
  `dbWriter · batch 500 / 100ms` → splits → `SQLite WAL` + `Hub → SSE`
- **On-screen text (per stage, as it lights):** `FanIn` · `Pool · NumCPU` ·
  `buffered 10,000` · `spill on backpressure` · `batch 500 / 100ms` · `SQLite WAL` ·
  `SSE live push`
- **Narration:** "Here's the whole thing. Any number of feeds — file tail, ticker,
  synthetic generator — fan in to a single line stream. A pool of NumCPU workers
  pulls from it, sniffs the vendor, parses, and validates OCSF required fields. They
  emit into a ten-thousand-deep buffered channel. One writer drains it, batching five
  hundred rows per hundred milliseconds into SQLite in WAL mode, and publishes the
  committed batch to a hub that fans out over Server-Sent Events."
- **B-Roll / text:** `Detect → Parse → Validate` shown as the three steps *inside*
  each worker, not as a separate box.
- **Audio intent:** explanatory, steady. The bed thins so the diagram reads.
- **Audio-coupled:** each stage illuminates on a beat as packets reach it.
- **Transition:** camera pushes into the worker box → Scene 6.

#### Scene 6 — The pluggable contract · 0:46–0:58 (12s)
- **Visual:** Code panel, `src/parser/parser.go:17-21`, three lines held large:
  ```go
  type Parser interface {
  	Name() string
  	Detect(line string) bool
  	Parse(line string) (schema.Event, error)
  }
  ```
  Beneath it, the three-step recipe reveals one line at a time:
  `1. Detect  — add a sniff rule          (~5 lines)`
  `2. Parse   — func ParseXxx(raw string)  (~100–300 lines)`
  `3. Register— Register("xxx", ParseXxx)  (~1 line)`
  A green badge lands: `Downstream changes: 0`
- **Narration:** "This is the entire contract. Three methods. Detect is a cheap
  substring sniff, Parse returns a canonical event. Onboard a vendor: add a sniff
  rule, write the parse function, call Register in an init. The pool, the channel,
  the writer, the database, the API, the SSE stream — none of it changes. We've done
  it four times."
- **B-Roll / text:** file:line reference `src/parser/parser.go:17`.
- **Audio intent:** confident, no swell. The proof is the code.
- **Audio-coupled:** the three recipe lines reveal on consecutive beats.
- **Transition:** code panel wipes left, stack table slides in → Scene 7.

#### Scene 7 — Stack & tradeoffs · 0:58–1:10 (12s)
- **Visual:** Five-row stack table. Each row lights with its tradeoff tag.
  | Layer | Choice | Why |
  |---|---|---|
  | Language | Go 1.27 | concurrency without a runtime |
  | Database | SQLite, `modernc.org/sqlite` | pure Go → `CGO_ENABLED=0`, air-gap |
  | API | `net/http` | REST + SSE, stdlib only |
  | Schema | OCSF-Slim v1.8 | your SIEM already validates this |
  | Deploy | static binary + one `.db` | that is the entire footprint |
  A tradeoff callout drops in amber:
  `Pure-Go SQLite costs real throughput. We took it for zero-dependency air-gap deploys.`
- **Narration:** "The stack is deliberately boring. Go for concurrency. SQLite via
  modernc — pure Go, so CGO is off and the binary drops onto an air-gapped host with
  no compiler. net/http for both REST and SSE. And OCSF-Slim, because your SIEM
  already knows what that is. The honest tradeoff: pure-Go SQLite is meaningfully
  slower than the CGO build. We bought air-gap deployability with it, knowingly."
- **B-Roll / text:** the tradeoff callout is the point of the scene — hold it ≥2s.
- **Audio intent:** matter-of-fact. No selling.
- **Audio-coupled:** rows reveal top-down on the beat grid.
- **Transition:** table folds into a git branch diagram → Scene 8.

#### Scene 8 — Branch honesty · 1:10–1:20 (10s)
- **Visual:** Git graph, two branches. Files fly from center into their branch.
  - **`main`** (merged · `go vet` clean · `go test ./...` pass):
    `src/parser/*.go` `src/schema/event.go` `utils/synth_*.go` `samples/`
  - **`feature/phase2-pipeline`** (built · unmerged):
    `src/pipeline/*.go` `src/output/*.go` `main.go` `Dockerfile` `API.md`
  Amber badge: `PERF_REPORT §7 · P0: README overstates main`
  Then a small honest line: `main.go on main is still "Hello World".`
- **On-screen text:** `Everything from here on: feature/phase2-pipeline.`
- **Narration:** "One thing before we go further, because it matters. The parsers and
  the schema are merged and tested on main — go vet is clean, the tests pass. The
  pipeline, the store, and the API you're about to see are built but not yet merged;
  they live on feature two-pipeline. Our own performance report already lists the
  mismatch as a P0 defect. Everything from here on is that branch. I'd rather you
  know than find out."
- **B-Roll / text:** the `Hello World` line stays on screen ≥2s. Do not rush it.
- **Audio intent:** the music drops out almost entirely. This is a trust beat.
- **Audio-coupled:** none. Deliberate silence under the honesty line.
- **Transition:** branch highlight collapses into the schema struct → Scene 9.

### ACT 2 — FEATURE DEEP DIVE & LIVE CODE WALKTHROUGH · 1:20–3:00 (100s)

#### Scene 9 — One schema · 1:20–1:34 (14s)
- **Visual:** `src/schema/event.go` — the `Event` struct scrolls; **required** fields
  illuminate: `class_uid` `time` `metadata` `raw_data` `raw_data_hash`. Then the
  formula types out:
  `type_uid = class_uid × 100 + activity_id`
  Two class cards land:
  **`4001` Network Activity** — category 4 — ASA, FortiGate, Linux
  **`2004` Detection Finding** — category 2 — Suricata
- **Narration:** "Everything normalizes into one struct, and it isn't a
  custom schema — it's OCSF-Slim one-point-eight, the standard your SIEM already
  validates. Type UID is derived, not guessed: class times one hundred plus
  activity. Four-oh-oh-one Network Activity for traffic. Two-oh-oh-four Detection
  Finding for IDS alerts. Two genuinely different event classes, one shape, one
  validator."
- **B-Roll / text:** `TypeUIDFor()` at `src/schema/event.go:145`.
- **Audio intent:** the argument lands. Let the formula hold.
- **Audio-coupled:** class cards land on two strong beats.
- **Transition:** camera zooms into `raw_data` → Scene 10.

#### Scene 10 — Losslessness (emotional payoff) · 1:34–1:48 (14s)
- **Visual:** Tight on the `raw_data` field. The full original UFW line types in,
  untouched, wrapping across the screen. Beside it, `raw_data_hash` computes —
  hex digits resolving one at a time. Big line lands: **`Nothing lost.`** Then:
  `You can recompute it.`
- **Narration:** "This is the field I care most about. Raw data, byte for byte, the
  exact line the device emitted — and beside it, the SHA-256 of that line. We didn't
  lose anything in normalization, and you don't have to trust us on that. Recompute
  the hash. It's right there."
- **B-Roll / text:** `HashRaw()` at `src/schema/event.go:276`; the
  ≤512-byte stack-buffer path visible.
- **Audio intent:** the one moment the music is allowed to be beautiful.
- **Audio-coupled:** hash digits resolve on the beat grid; `Nothing lost.` holds 1.6s.
- **Transition:** raw line slides right, four parser cards fly in → Scene 11.

#### Scene 11 — Four parsers, four strategies · 1:48–2:04 (16s)
- **Visual:** 2×2 grid. Each card: filename, method, and a real code signature.
  - **`src/parser/cisco_asa.go`** — Syslog regex · 8 compiled at package scope ·
    `%ASA-6-302013`, `106100`, `725001`
  - **`src/parser/fortigate.go`** — CEF, `logid`-keyed structured parse
  - **`src/parser/suricicata.go`** *(sic: `suricata.go`)* — EVE JSON, direct
    `encoding/json` decode · **zero regex**
  - **`src/parser/linux.go`** — regex + zero-alloc `strings.Index` field scan +
    stateful pairing
- **On-screen text:** `Same interface. Four completely different strategies.`
- **Narration:** "Four formats, four genuinely different strategies. Cisco ASA is
  syslog regex, and the eight patterns are compiled once at package scope — that's
  deliberate, and Act Three is about what happens when someone forgets. FortiGate is
  a logid-keyed structured parse. Suricata is a direct JSON decode with no regex at
  all. Linux is the hard one — regex for structure, a hand-rolled field scan for the
  key-value pairs, and stateful pairing."
- **B-Roll / text:** the real regex `var` block from `cisco_asa.go` and the real
  `extractField` from `linux.go`, side by side.
- **Audio intent:** brisk, comparative. Four beats, four cards.
- **Audio-coupled:** cards land one per beat, then all four hold.
- **Transition:** the Linux card expands to fill frame → Scene 12.

#### Scene 12 — One line, end to end · 2:04–2:22 (18s)
- **Visual:** Live walkthrough. The real line at the top:
  `myhost kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.148.10.88 DST=10.0.0.5 PROTO=TCP SPT=4444 DPT=22`
  Four steps run left→right, each highlighting as it executes:
  1. `DetectLinux` → `SRC=` && `DST=` → **match**
  2. `extractField(line, "SRC")` → `45.148.10.88` · `strings.Index` · **0 allocs**
  3. `extractField(line, "DPT")` → `22` → `NewEvent(4001, ActivityDeny, SeverityLow, …)`
  4. Result — a real OCSF card:
  ```json
  { "class_uid": 4001, "type_uid": 400102, "activity_name": "Deny",
    "src_endpoint": { "ip": "45.148.10.88", "port": 4444 },
    "dst_endpoint": { "ip": "10.0.0.5", "port": 22 },
    "raw_data": "myhost kernel: [UFW BLOCK] …",
    "raw_data_hash": "a3f1…" }
  ```
  The original line stays pinned at the top the whole time — the through-line.
- **Narration:** "One line, start to finish. Detect matches on SRC and DST. The field
  scan pulls the source IP with zero allocations. We map the action to Deny and
  severity Low, and build the canonical event. Class four-oh-oh-one, type four-oh-oh-
  one-oh-two, Deny. Source forty-five point one four eight, destination port
  twenty-two. And the original line is still sitting right there at the top of the
  screen, untouched, with its hash underneath."
- **B-Roll / text:** file:line for each step — `linux.go:44`, `linux.go:90`,
  `event.go:183`.
- **Audio intent:** the core demonstration. Music drops to a floor so the code reads.
- **Audio-coupled:** each step fires on a beat; the result card lands on a strong cue.
- **Transition:** result card expands into the channel → Scene 13.

#### Scene 13 — Backpressure, not silent drops · 2:22–2:34 (12s)
- **Visual:** `src/pipeline/pool.go` — `handle()` highlights the send:
  ```go
  select {
  case p.Out <- ev:                      // fast path
  case <-ctx.Done():
  case <-time.After(SpillTimeout):        // 2s
  	p.Stats.Spilled.Add(1)
  	spill(p.SpillDir, ev)                // to disk, never dropped
  }
  ```
  Simulated run: the channel gauge climbs to `10,000 / 10,000` (red), a worker waits,
  then `spill.jsonl` gets a line and the counter reads `spilled: 1`.
  Text: **`Backpressure, not silent drops.`**
- **Narration:** "What happens when the channel fills. Most pipelines drop, and the
  drop is invisible. This one waits two seconds, and if the writer still hasn't made
  room, it spills the event to disk and increments a counter. A saturated pipeline is
  something you can see in the stats and something you can replay. It is never
  something you find out about during an incident."
- **B-Roll / text:** `SpillTimeout = 2 * time.Second` at `src/pipeline/config.go:16` (phase-2).
- **Audio intent:** tension, then relief when the counter increments.
- **Audio-coupled:** gauge fill, then the spill tick.
- **Transition:** spill file streams into the writer batch → Scene 14.

#### Scene 14 — Single writer, idempotent restarts · 2:34–2:47 (13s)
- **Visual:** `src/output/db.go` — `RunWriter`. Batch fills to `500`, one transaction,
  WAL commit. `INSERT OR IGNORE` on `event_id` highlighted. Then a restart simulation:
  the same batch replays, and a `duplicates` counter stays flat — `0 new rows`.
  Then `EventsSince(ctx, sinceID, limit)` with the cursor diagram:
  `since_id=1000 → 1001…1100 → next_since_id=1100`
- **Narration:** "One writer, because SQLite allows one writer per file. It batches
  five hundred rows and commits them in a single transaction — the hundred-millisecond
  timer is only a trickle-latency backstop, because at load the batch always fills
  first. And the insert is INSERT OR IGNORE on the event ID, which means replaying a
  file after a crash cannot duplicate anything. Restarts are idempotent."
- **B-Roll / text:** `BatchSize = 500`, `FlushInterval = 100ms`,
  `RetentionRows = 1,000,000` at `src/output/db.go:23` (phase-2).
- **Audio intent:** steady, factual.
- **Audio-coupled:** batch counter ticks; commit lands on a beat.
- **Transition:** cursor arrow flies into the API panel → Scene 15.

#### Scene 15 — Two ways to consume · 2:47–3:00 (13s)
- **Visual:** Terminal panel, real endpoint shapes:
  ```
  GET /health
  GET /api/events?since_id=1000&limit=100   → {"events":[…],"next_since_id":1100}
  GET /stats                               → {received,parsed,failed,chan_depth,
                                              spilled,hub_dropped,db_rows}
  GET /stream                              → event: ulpf\ndata: {…}   (SSE, 15s heartbeat)
  ```
  Then a split panel: **`/api/events`** — cursor pull, history, no dupes no loss
  (SIEM backfill) vs **`/stream`** — live push, no replay (dashboard tail).
  Overlay: `slow client → dropped & counted, never stalls the writer`
- **Narration:** "Two ways to consume it. Cursor pull for history — ask for what's
  after this ID, get a next cursor back, no duplicates and no gaps. And Server-Sent
  Events for the live tail, with a fifteen-second heartbeat so proxies don't kill an
  idle stream. Slow subscribers get dropped and counted. The database write path
  never waits on a browser."
- **B-Roll / text:** the four routes from `src/output/api.go:25` (phase-2).
- **Audio intent:** closing the architecture. Bed returns to full.
- **Audio-coupled:** terminal lines type in; the split panel lands on a strong cue.
- **Transition:** the perf number slams in over it → Scene 16.

### ACT 3 — EDGE CASES, OPTIMIZATION & TESTING · 3:00–3:47 (47s)

#### Scene 16 — The 75× bug · 3:00–3:12 (12s)
- **Visual:** Before/after split, real code.
  **BEFORE** — `src/parser/linux.go:275`, `extractField`:
  ```go
  func extractField(line, key string) string {
  	re := regexp.MustCompile(`(?:^|\s)` + regexp.QuoteMeta(key) + `=([^\s]+)`)
  ```
  Annotation: **called 12× per line** (ID, SRC, DST, SPT, DPT, PROTO, IN, OUT, MAC,
  LEN, TOS, TTL) + 3 in `sshUser` + 1–2 in `linuxTimestamp` = **15–17 compilations
  per log line**, **~18 KB each**.
  **AFTER** — hand-rolled `strings.Index` scan with a manual boundary check. Returns
  a substring of the input, so it **allocates nothing**.
  Counter slams: `38,485 ns/line → 511 ns/line` · **`75×`**
  Secondary: `18,826 → 165 B/line` (**114× less**)
- **Narration:** "Here's the bug I want to show you, because it's the most
  instructive thing in this project. One function compiled a regex on every call. And
  it was called twelve times per line — twelve different fields — plus more in the
  timestamp and SSH paths. Fifteen to seventeen regex compilations for a single log
  line, at roughly eighteen kilobytes each. That's why Linux was six to sixteen times
  slower than every other parser. Replacing it with a hand-rolled index scan:
  thirty-eight thousand nanoseconds to five hundred and eleven. Seventy-five times
  faster, and it allocates nothing."
- **B-Roll / text:** note that `cisco_asa.go`, `fortigate.go`, and `suricata.go` were
  already correct — the defect was isolated to one file.
- **Audio intent:** the reveal. Hard contrast, before/after.
- **Audio-coupled:** counter slams on a strong cue. // beat-locked
- **Transition:** before/after splits into a scaling chart → Scene 17.

#### Scene 17 — The measurement that changed the plan · 3:12–3:23 (11s)
- **Visual:** Worker-scaling chart, real data from `PERF_REPORT.md` §4:
  baseline scaled **3.85× on 12 cores — 32% efficiency**. Correct Go scales
  near-linearly at this granularity, so 32% pointed at a shared non-CPU resource.
  Bars: `5,682 B/event` and `~594 MB/s` of garbage at 104k EPS.
  Then the fix result: `441 B/event` · `4.01 allocs/event` · `12.9×` less.
  Then a small honest check: `GOGC=400 → within 1–7% ⇒ not GC-bound anymore.`
- **Narration:** "The reason that mattered is stranger than 'it was slow.' The
  baseline scaled at three point eight five times on twelve cores — thirty-two
  percent. Correct Go goes near-linear at this granularity, so thirty-two percent
  meant we were saturating something that wasn't the CPU. At nearly six kilobytes
  allocated per event we were generating six hundred megabytes a second of garbage.
  We weren't compute-bound. We were memory-bandwidth-bound. And the confirmation:
  quadrupling the GC target afterwards changes throughput by one to seven percent.
  The allocation fix already took that win."
- **B-Roll / text:** the "confirming the bottleneck moved off the GC" experiment.
- **Audio intent:** analytical. This is the reasoning, not the result.
- **Audio-coupled:** bars grow in sequence.
- **Transition:** ingest ceiling bar appears, then gets cut in half by a second bar
  → Scene 18.

#### Scene 18 — Two ceilings (the honest twist) · 3:23–3:36 (13s)
- **Visual:** Two bars, wildly different heights, side by side.
  **`537,900 EPS`** — ingest / normalize (parser pool, 12 workers)
  **`16,700 rows/s`** — end-to-end incl. SQLite writer
  Caption: **32× apart.**
  Then the flat sweep — the proof: rows/s for 4, 8, 12, 16, 24 workers:
  `16,538 · 16,049 · 16,707 · 16,267 · 15,986` — **flat**.
  Then the isolated store number: `Store alone: 35,740 rows/s`.
  Then the twist, in amber: **`5.1× parser speedup bought +9.5% end-to-end.`**
- **Narration:** "And here's the number I want to be honest about. There are two
  ceilings, and they differ by thirty-two times. The parser pool can do five hundred
  thirty-seven thousand events per second. End to end, including the database, the
  system does sixteen thousand seven hundred. Here's the proof that the parser isn't
  the constraint: sweep the worker count from four to twenty-four and throughput
  doesn't move. Doubling the workers does nothing. Add the store in isolation and it
  does thirty-five thousand rows a second on its own. The limit is the single SQLite
  writer. So a five-point-one-times parser speedup bought us nine and a half percent
  end to end. The optimizations were correct and worth keeping — they cut garbage
  twelve-point-nine times, which is where even that nine and a half came from — but
  they do not move the product metric, because the product is not parser-bound."
- **B-Roll / text:** `PERF_REPORT.md` §1 and §6. State both numbers together or the
  537,900 figure misleads.
- **Audio intent:** the most important beat in the video. Let the flat sweep sit.
- **Audio-coupled:** the two bars land on consecutive beats, deliberately unequal.
- **Transition:** the DB row count and the parsed count drift apart → Scene 19.

#### Scene 19 — The 2.8% we were silently losing · 3:36–3:47 (11s)
- **Visual:** Two counters side by side, drifting apart:
  `parsed: 200,000` vs `db_rows: 194,377` — a red gap of `5,623 (2.8%)`.
  Cause traced on screen: `ParseLinux` derives the event UID from the IP-header
  `ID=` field at `src/parser/linux.go:90` — frequently `0` or repeated → distinct
  lines collide → `INSERT OR IGNORE` discards the loser **with no error and no
  counter movement**.
  Text: **`Silent data loss in a system whose selling point is losslessness.`**
- **Narration:** "And the measurement surfaced a correctness bug I want to put on
  camera. Both benchmark runs inserted two hundred thousand events. The database held
  a hundred and ninety-four thousand. Two point eight percent, silently deduplicated
  by INSERT OR IGNORE, with no error and no counter moving. The cause: the Linux
  parser derives its event ID from the IP header's ID field, which is frequently zero
  or repeats — so distinct lines collide and the loser is discarded. That is silent
  data loss in a system whose entire selling point is losslessness. It's fixed first
  in the roadmap, ahead of every performance item, because it is a correctness bug."
- **B-Roll / text:** the fix — use `HashRaw(raw)` as the UID, as Cisco and Suricata
  already do. Plus a `duplicates` counter in `Stats` so the loss can never be silent
  again.
- **Audio intent:** sober. This is the credibility peak of the video.
- **Audio-coupled:** the gap opens slowly. No sting — let it be uncomfortable.
- **Transition:** counters resolve into the test panel → Scene 20.

### ACT 4 — IMPACT, ROADMAP & CLOSING · 3:47–4:28 (41s)

#### Scene 20 — Testing & verification · 3:47–3:55 (8s)
- **Visual:** Terminal, real output captured from this repo:
  ```
  $ go build ./...          # clean
  $ go vet ./...            # clean
  $ go test ./...
  ok  	sih/src/parser
  ok  	sih/src/schema
  $ go test -race ./...
  ```
  Beside it: test coverage map — `cisco_asa_test.go` `fortigate_test.go`
  `suricata_test.go` `linux_test.go` `event_test.go` `uid_test.go` `bench_test.go`.
  Callout: `uid_test.go` proves the counter-based UID is *injective*, not just fast.
- **Narration:** "Build clean, vet clean, tests pass, race detector on. Beyond
  correctness there's a uniqueness test for the counter-based UID — because a fast
  ID generator is worthless if it collides, and injectivity is a claim you have to
  prove rather than assume."
- **B-Roll / text:** the actual `go test ./...` output from this working tree.
- **Audio intent:** brief, factual. This scene is receipts, not a highlight.
- **Audio-coupled:** none.
- **Transition:** terminal dissolves into the results table → Scene 21.

#### Scene 21 — Measured outcomes · 3:55–4:04 (9s)
- **Visual:** Results table, one row per beat, then all hold:
  | 4 | vendors → one OCSF-Slim v1.8 schema |
  | 2 | event classes — 4001, 2004 |
  | 88/90 | curated lines routed (by design) |
  | 8,000 | synthetic soak, zero failures |
  | 100,000 | Cisco soak, zero failures |
  | **75×** | slowest parser, 38,485 → 511 ns/line |
  | **12.9×** | less garbage per event |
  | **+9.5%** | end-to-end — reported as measured |
  | **2.8%** | silent loss found — and being fixed |
- **Narration:** "Four vendors into one schema. Two event classes. A hundred thousand
  lines with zero failures. A seventy-five-times fix on our slowest parser. Twelve
  point nine times less garbage. Nine and a half percent end to end, reported as
  measured rather than rounded up. And a two-point-eight-percent data-loss bug we
  found ourselves and are fixing first."
- **B-Roll / text:** the last two rows stay in amber. The honesty is the point.
- **Audio intent:** cumulative. Each row adds weight.
- **Audio-coupled:** rows reveal on the beat grid; last two land together.
- **Transition:** table slides left, roadmap column enters → Scene 22.

#### Scene 22 — Roadmap, prioritized honestly · 4:04–4:18 (14s)
- **Visual:** Prioritized column. P0 in red, P1 amber, P2 blue.
  **P0 — correctness, outranks all performance work**
  - Fix Linux `event_id` collision → use `HashRaw(raw)` as UID
  - Add a `duplicates` counter to `Stats` — make the loss visible
  - Fix the README to match `main`
  - **Decide the storage story** — at 16.7k rows/s the single writer caps the
    product. (a) accept & document the design point · (b) shard across N writers on
    N SQLite files — WAL allows one writer *per file*, so this scales near-linearly
    · (c) Postgres
  **P1** — `BatchSize` 500 → 2,000 · apply the `linux.go` treatment to
  `cisco_asa.go` (now slowest at 16,908 ns/line) · pre-size the FortiGate map
  **P2** — cheaper `Suricata.Detect` (524 ns/line) · drop the committed 17 MB
  `backend` binary
- **Narration:** "The roadmap, in the order we'd actually do it. First, correctness:
  fix the event ID collision, and add a duplicate counter so this class of loss can
  never be silent again. Fix the README. And then the decision that actually matters:
  the single SQLite writer caps this product at sixteen-seven thousand rows a second.
  Sharding across N writers on N files scales nearly linearly, because WAL allows
  one writer per file. That's a ten-to-hundred-times unlock, and it has nothing to do
  with parsing. Then the smaller items — bigger batches, and applying the Linux fix
  to Cisco, which is now our slowest parser."
- **B-Roll / text:** the `(a)/(b)/(c)` storage options, verbatim from `PERF_REPORT.md` §7.
- **Audio intent:** decisive. This is a team that knows what to do next.
- **Audio-coupled:** P0 block lands first and holds; P1/P2 follow on beats.
- **Transition:** roadmap collapses into the closing stack → Scene 23.

#### Scene 23 — Closing · 4:18–4:28 (10s)
- **Visual:** Return to the four raw lines from Scene 1 — but now aligned into one
  stack, one OCSF card beside them, hashes visible. The through-line closes.
  **ULPF** / `Four formats. One schema. Nothing lost —` / `and here's the hash to prove it.`
  / `github.com/… · branch: feature/phase2-pipeline` / `SIH 2026 · PS #25165 · CACHE ME OUTSIDE`
- **Narration:** "Four formats in. One schema out. Nothing lost — and a hash so you can
  check. Merged parsers today, pipeline and store on the phase-two branch, and a
  storage decision we're going to make deliberately rather than accidentally. Thanks."
- **B-Roll / text:** the four vendor chips, merged into one `OCSF-Slim v1.8` chip.
- **Audio intent:** resolution. The pad lands and holds.
- **Audio-coupled:** wordmark lands on the final strong cue. // beat-locked
- **Transition:** hold to end. No cut.

---

## 3. Reading-time audit

| Scene | On-screen words | Settled time | Floor | Verdict |
|---|---|---|---|---|
| 1 | 12 | ~4.5s | 0.8s/label | pass |
| 2 | 14 | ~5.5s | 4.2s | pass |
| 4 | 16 | ~6.0s | 4.8s | pass (hero) |
| 5 | 21 | ~9.0s | 6.3s | pass |
| 6 | 16 | ~7.5s | 4.8s | pass |
| 7 | 34 | ~7.0s | 10.2s | **tight — split the table across two beats, hold 4.5s each** |
| 8 | 20 | ~6.5s | 6.0s | pass |
| 9 | 18 | ~8.0s | 5.4s | pass |
| 10 | 8 | ~7.0s | 2.4s | pass (payoff) |
| 12 | 26 | ~11.0s | 7.8s | pass (code) |
| 15 | 30 | ~8.0s | 9.0s | **tight — type the terminal in two passes** |
| 18 | 28 | ~9.5s | 8.4s | pass (hero) |
| 19 | 22 | ~7.5s | 6.6s | pass |
| 21 | 34 | ~6.5s | 10.2s | **tight — reveal in two groups of 5, hold 3.5s each** |
| 22 | 58 | ~11.0s | 17.4s | **over — cut to P0 + the storage decision only; move P1/P2 to a static block with no reading requirement** |

Three scenes are flagged. The rule applied throughout: **cut copy, never speed up
type.** Scene 22 in particular sheds its P1/P2 detail rather than rushing 58 words
past the viewer.

---

## 4. Visual & audio production notes

### Visual identity (pulled from the project, not invented)

- **Background** `#07090d` — near-black, blue cast. SOC terminal.
- **Surface** `#0d1117` panels, `#161b22` raised, `#21262d` hairlines.
- **Text** `#e6edf3` primary, `#8b949e` secondary, `#6e7681` tertiary.
- **Accents** `#3ddc84` normalized/pipeline · `#4d9fff` OCSF structure ·
  `#ff5c5c` threat / loss / P0 · `#f5a524` raw / tradeoff / honesty badge.
- **Vendor chips** Cisco `#4d9fff` · FortiGate `#ff6b4a` · Suricata `#a78bfa` ·
  Linux `#f5a524`. Chips only, never as fill.
- **Type** `JetBrains Mono` for every log line, code block, field name, and number —
  it *is* the product's typeface. `Liberation Sans` for headline copy. No others.
  Both are system-local: no network at render, no FOUT, no missing glyphs.
- **Motifs** hairline grid (the data plane); the raw line's monospace gutter as the
  visual spine, present in Scene 1 and returned to in Scene 23; green = normalized,
  amber = raw, red = lost. Colour carries meaning and never decorates.

### Audio

- **Role:** warm technical bed. Present, never competing with code.
- **Track:** procedural bed generated for this video (see `work/audio.py`).
  A-minor, 100 BPM. No licensed asset, so the render is fully offline and
  reproducible.
- **Treatment:** enters at 0.6s under Scene 1, thins to a floor under every code
  scene (6, 12, 16, 20), returns to full at Scene 15, drops to near-silence for the
  Scene 8 honesty beat and the Scene 19 loss reveal, resolves on A at ~4:16 and holds
  to 4:28.
- **Arc:** tension (0–32s) → explanatory (32s–3:00) → analytical (3:00–3:47) →
  sober (3:47–4:18) → resolution (4:18–4:28).
- **Music cue guidance:** cues detected at composition time from the rendered bed
  (100 BPM, 0.6s grid). Three strong-cue locks only:
  - **4.05s** — Scene 1 final line lands (hook)
  - **121.0s** — Scene 16 the `75×` counter slam
  - **258.0s** — Scene 23 wordmark
  Everything else uses natural timing, and every sequential text reveal snaps to
  **every other beat**, never every beat — at 100 BPM consecutive beats are 0.6s
  apart, which is below the reading floor for a full line.
- **SFX posture:** sparse and low. Soft ticks on stage illumination, a low whoosh on
  the Scene 4 convergence, a sub hit on the Scene 2 red rule, a single warm hit when
  the Scene 13 spill counter increments, a dull thud on the Scene 19 gap opening.
  No SFX above 4 kHz. Nothing on the honesty beats.
- **Restraint rule:** no SFX in Scene 8. The music must not swell under the
  `Hello World` line — the joke is that it isn't a joke.
- **Narration:** script written in full in §2. **Not rendered** (no `--voice`).
  Music + SFX only in `brag.mp4`. The VO script is timed per scene so it can be
  recorded or synthesised later without re-cutting.

### Build & render

- Deterministic frame renderer: `render(t)` is a pure function of time, so any frame
  can be reproduced independently and the render is seek-safe.
- Headless Chromium at 1920×1080, `--force-color-profile=srgb`,
  `--font-render-hinting=none`, `--disable-lcd-text` so text weight is stable
  frame-to-frame.
- 268s × 30fps = **8,040 frames**. Stills reviewed for every scene *and* every
  mid-transition before the full render.
- `brag.jpg` pulled from the strongest settled frame — Scene 10, `Nothing lost.` with
  the hash fully resolved — and **baked as frame 0** so duration and audio sync are
  unchanged and every platform shows it as the idle thumbnail.
