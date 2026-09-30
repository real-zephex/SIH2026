# ULPF — Launch Video Plan

**Deliverable:** `brag.mp4` · 1920×1080 · 30fps · ~21s
**Tone:** `polished` with `default` pacing — confident, technical, no filler.
**Source material:** the real Go parsers in `src/parser/`, run against the real
sample captures in `samples/`. Every log line and every JSON field on screen is
genuine parser output captured in `work/real_output.txt`.

---

## 1. What it is

**One sentence:** ULPF turns whatever your perimeter devices emit into one
lossless OCSF stream that every SIEM already understands.

**Who it's for:** SOC analysts and security engineers who today hand-write a
parser per vendor before the SIEM can see anything.

**What it does for them:** deletes the per-vendor parser backlog — a new firewall
model becomes one small mapping, not a week of work.

**What sets it apart:** losslessness is not a promise, it's verifiable — every
event carries the original line byte-for-byte plus its sha256, so you can prove
nothing was dropped. And it runs air-gapped: one static binary, no cloud.

**Most impressive true claim:** four mutually incompatible formats — Cisco ASA
syslog, FortiGate key=value, Suricata EVE JSON, Linux netfilter — collapse into
one OCSF-Slim v1.8 schema (classes 4001 NetworkActivity and 2004
DetectionFinding), and the original bytes are still sitting right there next to
the normalized fields.

**Visual hook:** *the raw line never leaves the screen.* The video opens with
four incompatible vendor formats, and the whole piece is the moment they resolve
into one schema — while the original line stays untouched underneath, with its
hash. That contrast is the product's entire argument, so it should be the
through-line, not just one scene.

**Real flow to show:** raw line → `Detect` → `Parse` → `Validate` → OCSF event,
populated with actual output from the actual parsers.

**One-line share caption:** "Four firewall formats. One schema. Nothing lost —
and here's the hash to prove it."

---

## 2. Storyboard (21.0s)

| # | Scene | Dur | Content |
|---|-------|-----|---------|
| 1 | **HOOK — four languages** | 3.2s | Black. Four real raw lines arrive from four vendors, each with a colored vendor tag. They land at different x-offsets and don't align — visually incompatible. Caption: "Every device speaks its own language." Lines jitter/scan subtly. |
| 2 | **THE PROBLEM** | 2.6s | The four lines dim and stack left, compressed and unreadable. Right side: "4 formats. 4 parsers. 4 weeks." then the weeks counter ticks. The clutter *is* the argument. |
| 3 | **REVEAL — ULPF** | 2.8s | Lines snap into a single vertical stack (the pipeline). Wordmark **ULPF** resolves. Sub: "Universal Log Pre-processing Framework". A single OCSF card materialises on the right — the convergence moment. |
| 4 | **HIGHLIGHT 1 — one schema** | 3.6s | Close on the OCSF card. Fields illuminate in sequence with soft ticks: `class_uid 4001`, `type_uid 400101`, `src_endpoint`, `dst_endpoint`, `severity`. Then the Suricata finding drops in as `class_uid 2004 · Detection Finding` — **two classes, one schema**. |
| 5 | **HIGHLIGHT 2 — losslessness (punch)** | 4.2s | The camera settles on the `raw_data` field. It scrolls in full, untouched, with `raw_data_hash` computing and landing beside it. Big line: **"Nothing lost."** Then: "Prove it — sha256." The hash is real. This is the emotional payoff. |
| 6 | **HIGHLIGHT 3 + OUTRO** | 4.6s | Measured numbers, fast and factual: 4 vendors onboarded · 88/90 curated lines routed · 537,900 events/s ingest ceiling (12 workers) · air-gapped single binary. Then wordmark + OCSF-Slim v1.8 + repo. Land the share caption. |

**Pacing rule:** any line meant to be read stays fully settled ≥0.3s per word.
Scene 5's "Nothing lost." holds ~1.4s on its own.

**Transitions:** stagger, never crossfade two busy layouts. Old content exits
(translate + fade) → background dip → new content enters. Scene 1→2 and 5→6 dip
through near-black.

---

## 3. Visual identity

Pulled from the project's own world rather than invented:

* **Background** `#07090d` — near-black with a blue cast (terminal/SOC feel).
* **Accent** `#3ddc84` (green) for pipeline/normalized state; `#4d9fff` (blue)
  for OCSF structure; `#ff5c5c` (red) for threat/deny; `#f5a524` (amber) for
  the raw/unparsed side.
* **Vendor colors** (used only as thin tags, never as fill):
  Cisco `#4d9fff` · FortiGate `#ff6b4a` · Suricata `#a78bfa` · Linux `#f5a524`.
* **Type:** `JetBrains Mono` for every log line, JSON field and number — it *is*
  the product's typeface. `Liberation Sans` for headline copy. No other fonts.
* **Motifs:** a hairline grid (the "data plane"), a scanline sweep on the hook,
  and the raw line's monospace gutter as the visual spine of the whole piece.

---

## 4. Sound

One piece, mixed as a track rather than layered SFX. **Key: A minor, 100 BPM.**
Everything shares the key and the same short reverb so effects sit *in* the music.

* **Bed:** sub-bass pulse on every beat; a filtered saw pad entering at scene 3.
* **Arp:** 16th-note pluck (A2/C3/E3/G3) from scene 4, doubling into the
  field-illumination ticks so each tick is musical, not a click.
* **Riser:** filtered noise sweep 0→3.2s into the reveal.
* **SFX (soft, under the music):** low whoosh on the 4-lines-converge move; a
  single warm sub hit on "Nothing landed"; a soft tick per illuminated field.
* **Resolve:** pad + pluck resolve on A at 18.0s, gentle tail to 21.0s.
* **Mix:** music −6 dBFS peak, SFX −12 to −15 dBFS, no SFX above 4 kHz, master
  limited to −1 dBTP. Nothing harsh, nothing spiky.

---

## 5. Build

* Single self-contained HTML; every scene a layer; `render(t)` is a **pure
  function of time** so any frame can be reproduced independently.
* Playwright + Chromium (headless shell 153) screenshots each frame at 1920×1080;
  ffmpeg assembles to H.264.
* Fonts are system-local (JetBrains Mono, Liberation Sans) — no network at render
  time, so no FOUT and no missing-glyph risk.
* Stills reviewed for every scene *and* mid-transition before the full render.
* `brag.jpg` pulled from the strongest settled frame (scene 5, hash fully in)
  and **replaced** as frame 0 so duration and audio sync are unchanged.
