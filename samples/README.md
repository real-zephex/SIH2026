# Sample Logs — ULPF (SIH 25165)

Curated perimeter-device samples for parser dev. Real + synthetic, air-gap friendly.

| File | Source | Lines | Origin |
|---|---|---|---|
| `cisco_asa.log` | Cisco ASA Syslog | 20 | `elastic/integrations/packages/cisco_asa` `event.original` + Cisco ASA Syslog guide IDs 302013/302014/305011/106100/725001 |
| `fortigate.log` | FortiGate traffic/utm/event | 20 | `elastic/integrations/packages/fortinet_fortigate` `event.original` + `docs.fortinet.com` sample-logs-by-log-type |
| `paloalto_csv.log` | PAN-OS native CSV (THREAT/TRAFFIC) | 3 | `elastic/integrations/packages/panw` `event.original` |
| `paloalto_leef.log` | PAN-OS LEEF 1.0/2.0 + CEF | 5 | IBM QRadar DSM `palo-alto-pa-sample-event-message`, Palo Alto Custom Log Format docs |
| `suricata_eve.json` | Suricata EVE alert (JSONLines) | 30 | `github.com/FrankHassanabad/suricata-sample-data` `samples/wrccdc-2018/alerts-only.json` (207 alerts, first 30) + `docs.suricata.io` |
| `linux_iptables.log` | Linux netfilter/UFW/sshd (fallback 5th source) | 20 | `elastic/integrations/packages/iptables` `message` + live `journalctl -k`, `/var/log/kern.log`, `/var/log/ufw.log` patterns |
| `raw_downloads/` | ECS-parsed originals for reference | 7 files | elastic/integrations `sample_event.json` x6 + full 207-alert `suricata_alerts.json` |

## Regenerate / expand
```bash
# Suricata: 207 alerts
curl -sL -o samples/raw_downloads/suricata_alerts.json https://raw.githubusercontent.com/FrankHassanabad/suricata-sample-data/master/samples/wrccdc-2018/alerts-only.json
# DIY unlimited: pcap -> eve.json (air-gapped OK after download)
# from netresec.com / archive.wrccdc.org / malware-traffic-analysis.net:
suricata -r traffic.pcap -l ./out  # -> out/eve.json
# Linux live (this machine):
journalctl -k --no-pager | grep -iE 'UFW|IPTABLES|IN=.*OUT=' | head
```

## Linux network logs (Q2)
Yes — opt-in L3/L4 via netfilter, not full L7 by default:
- `iptables -A INPUT -j LOG --log-prefix "IPTABLES: "` / `nft ... log prefix` -> `/var/log/kern.log`, `/var/log/syslog`, `journalctl -k`
- `ufw logging on` -> `/var/log/ufw.log` (`[UFW BLOCK] IN=... SRC=... DST=... PROTO=TCP SPT= DPT=`)
- `conntrack -L`, `/proc/net/nf_conntrack`, `ulogd2` (JSON to userspace)
- L7 needs Suricata/Zeek on top; `tcpdump -w cap.pcap` + `suricata -r cap.pcap` closes the loop.
This box (archlinux): only `journalctl -k` kernel lines available, no syslog/ufw files — hence synthetic `linux_iptables.log` mirrors real format.
