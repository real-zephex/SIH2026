# ULPF API for the Next.js Dashboard

Base URL: `http://127.0.0.1:8080`. All responses are JSON except `/stream`
(SSE). No auth in Phase 2 (localhost/air-gap). CORS: same-origin assumed;
add headers in `src/output/api.go` if the Next.js dev server runs cross-origin.

Recommended client pattern: on page load fetch history via `/api/events`,
then open `/stream` for live rows. Keep the max `next_since_id` seen from
either path and resume polling with it after reconnects.

## GET /health

Liveness probe.

```
-> {"status":"ok","time":"2026-09-11T13:01:02Z"}
```

## GET /api/events?since_id=<rowid>&limit=<n>

Cursor pagination over committed events, ascending `id`.
Defaults: `since_id=0`, `limit=500` (clamped to 5000).

```
-> {
     "events": [ <OCSF Event>, ... ],
     "next_since_id": 87
   }
```

Empty page: `{"events":[],"next_since_id":<same>}`. Poll with
`since_id=<last next_since_id>`; rows are stable (SQLite `id` sequence,
`INSERT OR IGNORE` on `event_id` keeps restarts idempotent).

### Event object (OCSF-Slim v1.8)

| Field | Type | Notes |
|---|---|---|
| `class_uid` | int | `4001` NetworkActivity, `2004` DetectionFinding |
| `category_uid` | int | `4` Network, `2` Findings |
| `activity_id` | int | 4001: 1 Allow, 2 Deny; 2004: 1 Create |
| `type_uid` | int | `class_uid*100 + activity_id` |
| `severity_id` | int | 0 Unknown, 1 Info, 2 Low, 3 Medium, 4 High, 5 Critical |
| `time` | int | ms since epoch (UTC). Format client-side |
| `src_endpoint` / `dst_endpoint` | `{ip, port}` | `port` 0 = unknown/absent |
| `protocol_name` | string | `tcp`/`udp`/`icmp` (lowercase) |
| `direction` | string | `inbound`/`outbound`/`unknown` |
| `action` | string | vendor verb (`Built`, `Deny`, `pass`, `Alert`, …) |
| `traffic` | `{packets, bytes}` | counters, 0 when unknown |
| `message` | string | human-readable summary |
| `metadata` | object | `{product:{name,vendor,version}, version:"1.8.0", uid, correlation_uid}` — `uid` is the trace id |
| `raw_data` | string | original log line, byte-preserved |
| `raw_data_hash` | string | hex sha256 of `raw_data` |
| `finding_info` | string | 2004 only (e.g. Suricata signature) |
| `unmapped` | object | leftover vendor fields (≤20 keys) |
| `observables` | array | Linux parser emits `{name,type,value}` IP entries |

TypeScript sketch:

```ts
type Event = {
  class_uid: 4001 | 2004; type_uid: number; severity_id: number;
  time: number; src_endpoint: { ip?: string; port?: number };
  dst_endpoint: { ip?: string; port?: number };
  protocol_name?: string; action?: string; message?: string;
  metadata: { uid: string; product: { name: string; vendor: string } };
  raw_data: string; raw_data_hash: string;
  finding_info?: string; unmapped?: Record<string, string>;
};
```

## GET /stream (SSE)

Live tail of **committed** events. `Content-Type: text/event-stream`.

```
: connected

event: ulpf
data: {<OCSF Event>}

: heartbeat        <- every 15s, ignore (keep-alive for proxies)
```

Rules (locked):
* Only events committed **after** connect are sent — **no replay**. Fetch
  `/api/events` first for history, then attach here.
* One SSE frame per event: lines starting `data: ` carry exactly one JSON event.
* `: lines` (colon-prefixed) are comments — skip them.
* Reconnect with `Last-Event-ID` is accepted but ignored; resume via
  `/api/events?since_id=` instead.

JS sketch:

```js
const seen = new Set(); let cursor = 0;
// 1. history
for (;;) {
  const r = await fetch(`/api/events?since_id=${cursor}&limit=500`).then(r => r.json());
  r.events.forEach(e => { seen.add(e.metadata.uid); render(e); });
  cursor = r.next_since_id;
  if (!r.events.length) break;
}
// 2. live
const es = new EventSource('/stream');
es.addEventListener('ulpf', ev => {
  const e = JSON.parse(ev.data);
  if (!seen.has(e.metadata.uid)) { seen.add(e.metadata.uid); render(e); cursor++; }
});
```

## GET /stats

Pipeline + store counters for header cards.

```
-> {
  "received": 90, "parsed": 88, "failed": 2, "spilled": 0,
  "per_source": {"cisco_asa":20,"fortigate":20,"linux":18,"suricata":30},
  "chan_depth": 0, "db_rows": 87,
  "hub_subscribers": 1, "hub_dropped": 0
}
```

`failed` includes undetectable lines by design (Linux audit/sudo samples).
`spilled` > 0 means the 10k channel filled and raw lines went to `spill/`.
Poll every 2–5s; derive EPS client-side from deltas.
