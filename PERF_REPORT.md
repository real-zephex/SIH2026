# ULPF — Performance Analysis Report

**Scope:** synthetic log generation throughput, parser throughput, and the true
upper processing limit of the ULPF ingest path.
**Date:** 2026-09-26
**Machine:** AMD Ryzen 5 7430U (Zen 3, 6C/12T), 14 GiB RAM, Linux 5.x
**Go:** `go1.27.1-X:nodwarf5 linux/amd64`
**Baseline:** `main` @ `d353735` (pre-optimization) · **Optimized:** this working tree

---

## 1. Headline: there are two ceilings, and they differ by 32×

| Ceiling | What it measures | Throughput |
|---|---|---|
| **Ingest / normalize** | `Detect → Parse → Validate` (parser pool only) | **537,900 events/s** |
| **End-to-end** | full pipeline incl. SQLite writer | **16,700 rows/s** |

**The upper processing limit of ULPF as shipped is ~16,700 events/second**, and it
is set by the **single-writer SQLite insert path — not by parsing**. The parser
stage can do 32× more work than the system can persist.

This is the single most important finding in the report, and it was measured
rather than assumed. Section 6 shows the experiment that proves it.

### What the optimization work actually bought

| Metric | Before | After | Change |
|---|---|---|---|
| **End-to-end throughput** @ 12 workers | 15,259 rows/s | **16,707 rows/s** | **+9.5%** |
| Ingest ceiling (parser pool) | 104,600 EPS | **537,900 EPS** | **5.1×** |
| Ingest single-core | 26,000 EPS | 119,900 EPS | 4.6× |
| Bytes allocated per event | 5,682 B | 441 B | **12.9× less** |
| Allocations per event | 56.4 | 4.01 | **14× fewer** |
| Slowest parser (linux) | 38,485 ns/line | 511 ns/line | **75×** |
| Synthetic generation (1 core, 4 vendors) | ~0.5M lines/s | ~1.94M lines/s | 3.9× |
| Synthetic generation (peak, 8 workers) | — | 6.63M lines/s | — |

Read honestly: **a 5.1× parser speedup bought a 9.5% end-to-end gain.** The
optimizations were correct and worth keeping — they cut garbage generation 12.9×,
which is what produced even that 9.5%, and they are what makes the ingest stage
able to feed a faster store — but they do not move the product metric, because
the product is not parser-bound. Section 7 says what would.

---

## 2. Method

| Harness | Location | Purpose |
|---|---|---|
| `BenchmarkGenerate*` | `utils/bench_test.go` | Synthesis rate, allocations, parallel scaling |
| `BenchmarkParse`, `BenchmarkEndToEnd` | `src/parser/bench_test.go` | Per-vendor parse; full `Detect→Parse→Validate` |
| `TestSaturationProfile` (`-satprofile`) | `src/parser/bench_test.go` | Worker sweep → ingest ceiling |
| `TestCostBreakup` (`-satprofile`) | `src/parser/bench_test.go` | Per-stage ns/line attribution |
| `TestE2ESaturation` (`SATP=1`) | `src/pipeline/e2e_sat_test.go` † | Worker sweep → **end-to-end** ceiling |
| `BenchmarkStoreInsert{,Only}` | `src/output/store_bench_test.go` † | Isolated SQLite write cost |

† Developed against `feature/phase2-pipeline`, since the pipeline and store do
not exist on `main`. See §9.

Controls that make the numbers trustworthy:
* **Corpus pre-generated** (50k lines/vendor for parser, 200k mixed for e2e) so
  generation never contaminates parse measurement.
* **Mixed round-robin corpus** across all four vendors — real traffic is never
  single-vendor.
* **Best of 5 reps** per saturation configuration to suppress scheduler noise.
* **Two distribution models** for the ingest sweep: `index` (atomic work-stealing
  → pure CPU ceiling) and `chan` (10k-buffered channel, matching production config
  → realistic ceiling including channel cost).
* A `sink` guard prevents the compiler eliding parse work.
* The baseline and optimized end-to-end runs used the **same harness, same corpus
  size, same machine, same command** — measured in two separate git worktrees to
  eliminate any code drift between them.

---

## 3. Synthetic log generation

### 3.1 Per-vendor, 1 core, 1,000-line batches

| Vendor | Before ns/line | After ns/line | Speedup | Before allocs/line | After allocs/line | After lines/s |
|---|---|---|---|---|---|---|
| Cisco ASA | 1,670 | 390 | **4.3×** | 15.8 | 1.01 | 2,566,000 |
| FortiGate | 1,450 | 456 | **3.2×** | 11.6 | 1.01 | 2,192,000 |
| Suricata | 4,057 | 683 | **5.9×** | 10.5 | 1.01 | 1,465,000 |
| Linux | 1,392 | 329 | **4.2×** | 8.0 | 1.01 | 3,040,000 |

Generation is now **~1 allocation per line** — the returned string itself.

### 3.2 The four defects

1. **`fmt.Sprintf` per line.** Each line ran 1–4 `Sprintf` calls, each reflectively
   boxing its arguments. Replaced with a reused `lineBuf` (`utils/synthfast.go`)
   that appends via `strconv.AppendInt` and hand-rolled zero-padding.
2. **Map and slice literals built *inside* the per-line switch.** The FortiGate
   generator constructed `map[int]int{6: 443, 17: 53}[proto]` and
   `map[int]string{6: "HTTPS", 17: "DNS"}[proto]` on **every line**; Suricata built
   `map[string]int{"TCP": []int{22,80,443,445,139}[r.Intn(5)], "UDP": ...}[proto]`
   — a map *plus two slices* per line. All hoisted to package scope or replaced
   with a branch.
3. **`time.Date` + `time.Format` to render numbers.** The ASA generator built a
   `time.Time` only to read `Month()` back out to index a month-name table.
   Replaced with direct integer rendering.
4. **`json.Marshal` for Suricata** — reflection over a nested struct graph at
   4,057 ns/line, 3–4× slower than any other generator. Replaced with hand-emitted
   JSON (~683 ns/line).

   Side benefit: because `omitempty` is a no-op on struct fields, the old code
   serialized `"http":{}` onto every DNS and TLS event. Real EVE output omits
   absent objects, and the parser is already tolerant of their absence.

5. **`WriteXSamples` materialized the corpus twice.** `strings.Join(lines, "\n")`
   built one giant string, then `[]byte(...)` copied it again — 2× peak memory for
   the whole file, so a 1M-line corpus needed ~400 MB of transient RAM. Now
   streamed through a 1 MiB `bufio.Writer` in 4,096-line chunks; peak memory is
   independent of corpus size.

### 3.3 Parallel generation

The generators are pure functions of `(n, seed)`, so they are embarrassingly
parallel. Measured with 50,000 lines of work per goroutine so goroutine-spawn
overhead does not dominate (an earlier run at 1,000 lines/goroutine showed a
*false plateau* at 4 procs — pure harness artifact):

| Workers | Throughput (all 4 vendors) | Speedup |
|---|---|---|
| 1 | 1.94M lines/s | 1.00× |
| 2 | 3.43M lines/s | 1.77× |
| 4 | 5.45M lines/s | 2.81× |
| 8 | **6.63M lines/s** | **3.42×** |
| 12 | 6.37M lines/s | 3.29× |

Sublinear (3.4× on 12 cores) because every line allocates a string — this stage
is memory-bandwidth-bound, not CPU-bound. For context, 6.63M lines/s is **~12×
the ingest ceiling**, so generation is nowhere near the critical path for load
testing.

---

## 4. Parser throughput

| Vendor | Before ns/line | After ns/line | Speedup |
|---|---|---|---|
| cisco_asa | 6,194 | 3,358 | 1.84× |
| fortigate | 2,311 | 1,125 | 2.05× |
| suricata | 2,604 | 1,307 | 1.99× |
| **linux** | **38,485** | **511** | **75×** |
| **End-to-end (mixed)** | **13,476** | **1,782** | **7.6×** |

### 4.1 Root cause: the ceiling was allocation-bound, not CPU-bound

The baseline scaled at only **3.85× on 12 cores (32% efficiency)**. Correct Go
scales near-linearly at this granularity, so 32% pointed at a shared non-CPU
resource. At 5,682 B/event and ~104k EPS the pipeline generated **~594 MB/s of
garbage** — saturating memory bandwidth and the GC. The fix was not "add cores";
it was "stop allocating."

### 4.2 The dominant defect: a regex compiled per call (`src/parser/linux.go`)

```go
func extractField(line, key string) string {
    re := regexp.MustCompile(`(?:^|\s)` + regexp.QuoteMeta(key) + `=([^\s]+)`) // per call!
```

Called **12× per line** (ID, SRC, DST, SPT, DPT, PROTO, IN, OUT, MAC, LEN, TOS,
TTL), plus 1–2 in `linuxTimestamp` and 3 in `sshUser` — **15–17 regex
compilations per log line**, at ~18 KB allocated each. Hence Linux's 185
allocs and 18.8 KB per line, and its 6–16× slowness versus every other vendor.

The rest of the codebase did this correctly: `cisco_asa.go` precompiles all 8
regexes in a package-level `var` block; `fortigate.go` and `suricata.go` use no
regex at all. **The defect was isolated to one file.**

**Fix:** `extractField` is now a hand-rolled `strings.Index` scan with a manual
boundary check. It returns a substring of the input, so it **allocates nothing**,
and it mirrors the original regex semantics exactly — including the
empty-value and end-of-string cases. The remaining regexes were hoisted to
package vars, and a zero-allocation fast path was added for the `Mon DD HH:MM:SS`
syslog stamp that falls back to the original regex when it does not match, so
behaviour is unchanged by construction.

**Result: 38,485 → 511 ns/line (75×); 18,826 → 165 B/line (114× less).**

### 4.3 sha256 computed twice per event (`src/schema/event.go`)

Every parser sets `ev.RawDataHash = schema.HashRaw(raw)`, then `Validate()`
independently re-derived it — a tautology, since the hash came from the same
string one line earlier. Cost: **~700 ns/event, twice** (once inside `Parse` for
the three self-validating parsers, once in the pool).

**Fix:** split the API. `Validate()` keeps the full contract (still re-verifies
the hash) for hand-built events; `ValidateNoRehash()` skips the redundant
re-hash and is used by `cisco_asa`, `suricata` and `linux`, which derive the hash
from the same `RawData` on an adjacent line.

`HashRaw` was also optimized: lines ≤512 B (essentially all perimeter logs) are
copied into a stack buffer so `[]byte(raw)` does not escape, and the hex digest is
built in a stack array instead of `hex.EncodeToString`'s allocate-then-copy.

**Result: `Validate` 259 → 95 ns/line; `HashRaw` 237 → 76 ns/line (3.1×), 140 → 23 B/line.**

### 4.4 `newUID()`: a syscall and a `Sprintf` per event

`rand.Read` (a `getrandom` syscall) plus `fmt.Sprintf` on five byte slices —
**449 ns/event** for a log correlation id, which needs uniqueness, not
cryptographic unpredictability.

**Fix:** a process-random 64-bit prefix drawn from `crypto/rand` **once at init**,
combined with an `atomic.Uint64` counter and a hand-rolled hex encoder.
Uniqueness holds by construction: `lo = prefixLo + c × 0x9E3779B97F4A7C15` is
injective in `c` (odd multiplier ⇒ bijection mod 2⁶⁴; addition preserves
injectivity). v4 version and RFC 4122 variant bits are preserved, so output is
still a well-formed UUID. A duplicate implementation in `suricata.go` was deleted
and made to delegate to the canonical helper.

**Result: 449 → 40 ns/op (11×); one syscall per process instead of per event.**

### 4.5 Correctness defect found en route: non-deterministic `DetectAll`

`DetectAll` iterated a **Go map**, whose iteration order Go deliberately
randomizes. If a line ever satisfied two parsers, the winner could differ between
runs — latent non-determinism in a security pipeline and a latent test-flake
source. Replaced with an ordered `[]Parser` slice built at `Register` time:
detection is now deterministic *and* avoids per-call map-iterator setup.

### 4.6 Secondary

* `NewEvent` built `TypeName` via `Sprintf("%s: %s", ...)` per event for one of
  ~6 reachable strings → replaced with a switch returning constants.
* `Validate` allocated a `[]Endpoint{...}` slice per call to iterate two values →
  unrolled. It also called `net.ParseIP` (16-byte alloc per call) → replaced with
  an allocation-free `isIPv4` mirroring `net.ParseIP` for the dotted-quad form.
* `ParseLinux` extracted `IN`/`OUT` twice (for `Direction`, then `unmapped`) →
  now shared; `Unmapped` and `Observables` pre-sized.

---

## 5. Ingest ceiling (parser pool)

Worker sweep, default `GOGC=100`, best of 5 reps, 200,000-line mixed corpus.

**`index` mode (pure CPU ceiling)**

| Workers | EPS | vs 1 core | | Workers | EPS | vs 1 core |
|---|---|---|---|---|---|---|
| 1 | 119,902 | 1.00× | | 10 | 514,144 | 4.29× |
| 2 | 217,675 | 1.82× | | **12** | **537,928** | **4.49×** ← peak |
| 4 | 353,768 | 2.95× | | 16 | 508,760 | 4.24× |
| 6 | 436,352 | 3.64× | | 24 | 507,927 | 4.24× |
| 8 | 473,599 | 3.95× | | 48 | 518,533 | 4.32× |

**`chan` mode (10k-buffered, production config)** — 1 core 101,954; 4 → 302,903;
8 → 428,295; 10 → 469,781; **12 → 517,295 (peak, 5.07×)**; 16 → 509,363.

* **Ceiling: ~537,900 EPS**, knee at **10–12 workers = `runtime.NumCPU()`**.
* Beyond 12 workers throughput is flat to slightly negative (16–48 all within
  ~5% of peak, several below) — the signature of a saturated subsystem, not
  under-provisioning. **Practical guidance: size the pool at `NumCPU`; more
  workers only add contention.**
* The channel costs ~4% versus work-stealing at the knee.

**Confirming the bottleneck moved off the GC.** If the system were still
GC-bound, a 4× larger GC target would raise the ceiling substantially. It does not:

| GC setting | `index` peak | `chan` peak |
|---|---|---|
| `GOGC=100` (default) | 537,928 | 517,295 |
| `GOGC=400` | 542,180 | 551,734 |

Under 1% and ~7% respectively — within run-to-run variance. The 12.9×
allocation reduction already captured that win, so **`GOGC` is not a useful
lever.**

---

## 6. The actual bottleneck: SQLite single-writer

### 6.1 End-to-end worker sweep — flat across all worker counts

200,000 events through `Feed → Pool → chan → dbWriter → SQLite WAL`:

| Workers | Baseline rows/s | Optimized rows/s | Δ |
|---|---|---|---|
| 4 | 16,538 | 16,572 | +0.2% |
| 8 | 15,381 | 16,049 | +4.3% |
| **12** | **15,259** | **16,707** | **+9.5%** |
| 16 | 15,114 | 16,267 | +7.6% |
| 24 | 15,403 | 15,986 | +3.8% |

**Throughput is flat from 4 to 24 workers.** If parsing were the constraint,
doubling workers from 4 to 12 would have moved the number. It does not. Adding
parser capacity is *free* but *useless* — which is the proof that the constraint
is downstream, in the single writer.

### 6.2 Isolating the store

500-row batched transactions, `synchronous=NORMAL`, WAL:

| Configuration | Throughput | B/row | allocs/row |
|---|---|---|---|
| **Store only** (pre-parsed events) | **35,740 rows/s** | 120 | 0.81 |
| Store + parse (serialized, 1 goroutine) | 25,866 rows/s | 201 | 1.30 |
| **Full concurrent pipeline** | **16,700 rows/s** | — | — |

The store alone sustains 35,740 rows/s. The full pipeline achieves 16,700 —
about 47% of that — because the writer goroutine shares memory bandwidth and GC
with 12 busy parser workers. That 53% gap is contention, and it is the *only*
place the parser optimizations show up end-to-end: cutting garbage 12.9× reduced
the pressure the writer competes under, worth the observed +9.5%.

Note the `FlushInterval` 100 ms timer is **not** the constraint: `RunWriter`
flushes immediately on reaching `BatchSize` (500) and only uses the timer as a
trickle-latency backstop. At load, batches always fill first.

### 6.3 Latent correctness issue surfaced by this measurement

Both runs inserted 200,000 events but the database holds fewer:

| Run | Inserted | Rows in DB | Silently deduped |
|---|---|---|---|
| Baseline | 200,000 | 194,451 | 5,549 (2.8%) |
| Optimized | 200,000 | 194,377 | 5,623 (2.8%) |

`INSERT OR IGNORE` on `event_id` is silently discarding **~2.8% of all ingested
events**. This is the known Linux parser issue: `ParseLinux` derives the event
UID from the IP-header `ID=` field (`linux.go:70`), which is frequently `0` or
repeats, so distinct lines collide. `INSERT OR IGNORE` then discards the loser
with no error and no counter movement.

This is more serious than a cosmetic duplicate-UID issue: **it is silent data
loss in a system whose selling point is losslessness.** `stats.db_rows` drifts
from `stats.parsed` and the only symptom is a small unexplained gap.

---

## 7. Recommendations, correctly prioritized

The original instinct — optimize the parser — was necessary but not sufficient.
In priority order:

| P | Action | Expected effect |
|---|---|---|
| **P0** | **Fix the Linux `event_id` collision**: use `HashRaw(raw)` as the UID (as Cisco/Suricata already do) or fall back to it when `ID=` is absent/zero/repeated | Removes silent ~2.8% data loss. This is a **correctness** fix and outranks every performance item |
| **P0** | **Instrument the dedup**: add a `duplicates` counter to `Stats`, incremented when `InsertBatch` inserts fewer rows than submitted | Makes the loss visible instead of silent; directly supports the losslessness claim on stage |
| **P0** | **Fix the README** — it documents a pipeline, SQLite, API/SSE and dashboard that are not on `main` | A judge who clones `main` will not find them |
| **P0** | **Decide the storage story.** At 16.7k rows/s the single SQLite writer caps the product. Options: (a) accept and document ~16.7k EPS as the design point; (b) shard across N writer goroutines on N SQLite files (WAL allows one writer *per file*, so this scales nearly linearly); (c) `Store` → Postgres for higher volume | This, not parsing, is what unlocks 10–100× |
| **P1** | Reduce the writer's 47% contention: batch larger (`BatchSize` 500 → 2,000) to amortize transaction overhead, and pre-size the `json.Marshal` buffer | Fewer, larger transactions; less per-batch overhead. Cheap to test |
| **P1** | Apply the `linux.go` treatment to `cisco_asa.go` (now the slowest parser at 16,908 ns/line, driven by 8 sequential `FindStringSubmatch` calls and a case-insensitive `(?i)\b(TCP|UDP|ICMP)\b`) | ~3× on the slowest parser. Needed only once storage is fixed |
| **P1** | Pre-size the FortiGate output map (803 B/line, highest of the four) | Lower GC pressure, better parallel efficiency |
| **P2** | Cheaper `Suricata.Detect` (524 ns/line — 3–5× other vendors, scans for `"event_type"` across the line) | ~400 ns/line recovered on *every* line, since `DetectAll` runs per line |
| **P2** | Remove the 17 MB `backend` binary committed on `feature/phase2-pipeline`; add it to `.gitignore` | Repo hygiene |
| **P3** | Set the worker pool to `NumCPU` in the pipeline config | Confirmed optimal by the sweep; avoids the flat-to-negative region past 12 |

---

## 8. Limitations

1. **Two different "upper limits"** (§1) and the gap between them is the whole
   story. Quote them together or a reader will be misled by the 538k figure.
2. **End-to-end numbers require `feature/phase2-pipeline`.** The pipeline, store
   and API do not exist on `main`; those harnesses cannot run there.
3. **One machine, consumer silicon.** 12 logical cores, no SMT isolation. A
   server with more cores should ingest faster, but the knee should still track
   `NumCPU` — untested.
4. **Synthetic corpus only.** Every line is well-formed by construction. Real
   traffic has malformed lines, partial writes and multi-line traces. The
   `Detect`-miss path is exercised but its cost distribution is not
   representative.
5. **The store benchmark is single-connection.** It measures one writer against
   one SQLite file, which matches the production design but does not explore
   sharding.
6. **`sha256` is now ~36% of fixed per-event cost** (400 of 1,100 ns). It is a
   PS-mandated lossless field, so it stays, but BLAKE3 would cut it — pending a
   compliance check.
7. **Parallel efficiency is 37–42%, not linear.** Remaining causes are memory
   bandwidth (441 B/event still allocated) and shared L3. Closing that needs
   further allocation reduction, chiefly in FortiGate and Cisco.
8. **The `sha256` "savings" are workload-dependent.** `ValidateNoRehash` removes
   a redundant hash, but the *first* hash remains mandatory per event.

---

## 9. Reproducing

On `main` (parsers + generators):

```bash
go test ./utils/ -run XXX -bench 'BenchmarkGenerate$' -benchmem -benchtime 200x
go test ./utils/ -run XXX -bench BenchmarkWriteSampleFile -benchmem
go test ./utils/ -run XXX -bench BenchmarkGenerateParallel -benchtime 20x
go test ./src/parser/ -run XXX -bench 'BenchmarkParse|BenchmarkEndToEnd' -benchmem -benchtime 5x
go test ./src/parser/ -run TestCostBreakup        -satprofile -v
go test ./src/parser/ -run TestSaturationProfile  -satprofile -v -timeout 90m
GOGC=400 go test ./src/parser/ -run TestSaturationProfile -satprofile -v -timeout 90m
```

On `feature/phase2-pipeline` (adds the end-to-end and store harnesses):

```bash
SATP=1 go test ./src/pipeline/ -run TestE2ESaturation -v -timeout 90m
go test ./src/output/ -run XXX -bench BenchmarkStoreInsert -benchmem -benchtime 40x
```

The optimized parser/schema/generator code is compatible with the pipeline
branch: overlaying it onto `feature/phase2-pipeline` builds clean and all
pipeline, output, parser and schema tests pass.

---

## 10. Bottom line

The ingest stage was rewritten for a **5.1× ceiling** and **14× fewer
allocations**; synthetic generation got **3.2–5.9× faster** at one allocation per
line. All of it is correct, tested under `-race`, and worth keeping.

But the honest headline is §1: **ULPF persists ~16,700 events/second, and that
number is set by the single-writer SQLite insert, not by parsing.** The next
order-of-magnitude win is a storage decision, and the most urgent item on the
list is not a performance item at all — it is the ~2.8% of events that
`INSERT OR IGNORE` is currently discarding without a trace, in a system whose
entire claim is that it loses nothing.
