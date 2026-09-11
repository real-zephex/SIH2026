# REQS — Ingestion Sources (ULPF / SIH 25165)

Scope: perimeter network devices only (`ps.md:43`). 4 sources (3 must + 1 stretch) + 1 fallback. One dev per source.

## Must (demo-blocking)

### 1. Cisco ASA Firewall — unstructured Syslog
- Format: RFC3164 Syslog, `%ASA-<sev>-<id>: <msg>`.
- IDs: 302013/302014 (conn build/teardown), 305011/305012 (NAT), 106100 (ACL), 106023 (deny), 725001/725002 (SSL).
- Sample: `samples/cisco_asa.log` (20 lines).
- Detect: contains `%ASA-`. Parse: header + id + `inside:ip/port -> outside:ip/port`.
- Ref: `samples/raw_downloads/cisco_asa_ecs.json` (`event.original`), Cisco ASA Syslog guide.

### 2. FortiGate Firewall — structured Syslog / CEF kv
- Format: `date= time= logid= type=traffic|utm|event subtype= ... srcip= dstip= srcport= dstport= proto= action=`.
- Types: traffic forward/local, utm app-ctrl/virus/ips/webfilter, event system/user/vpn.
- Sample: `samples/fortigate.log` (20 lines).
- Detect: contains `logid=` + `srcip=`. Parse: kv tokenizer (quoted values).
- Ref: `samples/raw_downloads/fortigate_ecs.json`, `docs.fortinet.com` sample-logs-by-log-type.

### 3. Suricata IDS/IPS — EVE JSON
- Format: JSONLines, `{"timestamp","event_type":"alert|http|dns|flow","src_ip","dest_ip","proto","alert":{...}}`.
- Sample: `samples/suricata_eve.json` (30 lines; full 207 in `samples/raw_downloads/suricata_alerts.json`).
- Detect: starts with `{` + contains `"event_type"`. Parse: `encoding/json`.
- Ref: `github.com/FrankHassanabad/suricata-sample-data`, `docs.suricata.io`.

## Stretch (ship if green before hour 10)

### 4. Palo Alto PAN-OS — CSV + LEEF/CEF
- Formats: (a) native CSV `...,THREAT|TRAFFIC,...,src,dst,sport,dport,proto,action,...`, (b) `LEEF:1.0|2.0|...|src= dst= srcPort= dstPort= proto= action=`, (c) `CEF:0|...|src= dst= spt= dpt=`.
- Samples: `samples/paloalto_csv.log` (3) + `samples/paloalto_leef.log` (5).
- Detect: contains `LEEF:` or starts with `CEF:` or matches PAN-OS CSV (`THREAT,|TRAFFIC,`).
- Ref: `samples/raw_downloads/panw_ecs.json` (`event.original`), IBM QRadar `palo-alto-pa-sample-event-message`.

## Fallback (always works, air-gap demo insurance)

### 5. Linux netfilter / UFW / sshd
- Format: `SRC= DST= LEN= PROTO=TCP SPT= DPT=`, `[UFW BLOCK|ALLOW] IN=...`, sshd auth lines.
- Sample: `samples/linux_iptables.log` (20 lines).
- Detect: contains `SRC=` + `DST=` or `[UFW` or `sshd[`.
- Ref: `samples/raw_downloads/iptables_ecs.json` (`message`), live: `journalctl -k | grep -iE 'UFW|IPTABLES|IN='`.

## Parser contract (all sources)
`Detect(line) bool` cheap prefix sniff -> `Parse(line) (schema.Event, error)` mapping to `src/schema/event.go` (4001 Network / 2004 Finding). Every event keeps `raw_data + raw_data_hash + metadata.uid`. Overflow vendor fields -> `unmapped` (cap 20). Golden test: 1 sample file each, all lines must parse + `Validate()` pass.
