package utils

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"
)

// GenerateLinux returns n synthetic Linux firewall/SSH log lines in the same
// shapes as samples/linux_iptables.log: [UFW BLOCK]/[UFW ALLOW]/[IPTABLES-DROP]
// netfilter lines (SRC=/DST=/SPT=/DPT=/PROTO=), [NEW SSH] lines, and sshd
// Failed/Accepted password lines. Every line is DetectLinux-detectable.
// seed=0 uses time-based randomness; pass a fixed seed for reproducible tests.
func GenerateLinux(n int, seed int64) []string {
	if n <= 0 {
		return nil
	}
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	r := rand.New(rand.NewSource(seed))
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, synthLinux(r, i))
	}
	return out
}

// WriteLinuxSamples writes n synthetic lines to path (one per line).
func WriteLinuxSamples(path string, n int, seed int64) error {
	lines := GenerateLinux(n, seed)
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

var linuxUsers = []string{"admin", "root", "zephex", "ops", "deploy", "ubuntu"}

func synthLinux(r *rand.Rand, i int) string {
	// Attacker-style public source vs internal source mix.
	src := fmt.Sprintf("45.148.%d.%d", r.Intn(30)+10, 2+r.Intn(250))
	if r.Intn(4) == 0 {
		src = fmt.Sprintf("192.168.%d.%d", 1+r.Intn(3), 2+r.Intn(250))
	}
	dst := []string{"10.0.0.5", "10.4.0.5", "172.18.0.5"}[r.Intn(3)]
	sport := 1024 + r.Intn(60000)
	dport := []int{22, 22, 22, 80, 443, 53}[r.Intn(6)]
	ttl := 52 + r.Intn(13)
	id := 10000 + r.Intn(50000)
	mac := "MAC=90:10:20:76:8d:20:90:10:65:29:b6:2a:08:00 "
	if r.Intn(3) == 0 {
		mac = ""
	}
	ts := linuxSynthTimestamp(r)

	switch r.Intn(8) {
	case 0, 1: // [UFW BLOCK] TCP (most common, samples lines 2, 8, 11-20)
		return fmt.Sprintf("%smyhost kernel: [UFW BLOCK] IN=eth0 OUT= %sSRC=%s DST=%s LEN=60 TOS=0x00 PREC=0x00 TTL=%d ID=%d DF PROTO=TCP SPT=%d DPT=%d WINDOW=64240 RES=0x00 SYN URGP=0",
			ts, mac, src, dst, ttl, id+i, sport, dport)
	case 2: // [UFW ALLOW] (samples line 3)
		if r.Intn(2) == 0 {
			return fmt.Sprintf("%smyhost kernel: [UFW ALLOW] IN=eth0 OUT= %sSRC=%s DST=%s LEN=84 TOS=0x00 PREC=0x00 TTL=64 ID=%d PROTO=ICMP TYPE=8 CODE=0 ID=1 SEQ=%d",
				ts, mac, src, dst, id+i, r.Intn(100))
		}
		return fmt.Sprintf("%smyhost kernel: [UFW ALLOW] IN=eth0 OUT= %sSRC=%s DST=%s LEN=52 TOS=0x00 TTL=64 ID=%d PROTO=TCP SPT=%d DPT=22 WINDOW=2853 RES=0x00 ACK URGP=0",
			ts, mac, src, dst, id+i, sport)
	case 3: // [IPTABLES-DROP] (samples line 4)
		return fmt.Sprintf("%smyhost kernel: [IPTABLES-DROP] IN=eth0 OUT= %sSRC=%s DST=%s LEN=52 TOS=0x00 PREC=0x00 TTL=%d ID=%d DF PROTO=TCP SPT=%d DPT=443 WINDOW=2853 RES=0x00 ACK URGP=0",
			ts, mac, src, dst, ttl, id+i, sport)
	case 4: // [NEW SSH] (samples line 10)
		return fmt.Sprintf("%smyhost kernel: [NEW SSH] IN=eth0 OUT= SRC=%s DST=%s LEN=60 PROTO=TCP SPT=%d DPT=22 SYN URGP=0",
			ts, src, dst, sport)
	case 5: // sshd Failed password (samples line 6)
		user := linuxUsers[r.Intn(len(linuxUsers))]
		if r.Intn(2) == 0 {
			return fmt.Sprintf("%smyhost sshd[%d]: Failed password for invalid user %s from %s port %d ssh2",
				linuxSyslogPrefix(r), 1000+r.Intn(9000), user, src, sport)
		}
		return fmt.Sprintf("%smyhost sshd[%d]: Failed password for %s from %s port %d ssh2",
			linuxSyslogPrefix(r), 1000+r.Intn(9000), user, src, sport)
	case 6: // sshd Accepted password (samples line 7)
		user := linuxUsers[r.Intn(len(linuxUsers))]
		return fmt.Sprintf("%smyhost sshd[%d]: Accepted password for %s from %s port %d ssh2",
			linuxSyslogPrefix(r), 1000+r.Intn(9000), user, src, sport)
	default: // generic filter verdict line, SRC/DST only (samples line 1 style)
		verdict := []string{"wan-lan-default-D", "lan-wan-accept-A"}[r.Intn(2)]
		return fmt.Sprintf("%sHostname kernel: [%s]IN=eth0 OUT= %sSRC=%s DST=%s LEN=52 TOS=0x00 PREC=0x00 TTL=%d ID=%d DF PROTO=TCP SPT=%d DPT=443 WINDOW=2853 RES=0x00 ACK URGP=0",
			ts, verdict, mac, src, dst, ttl, id+i, sport)
	}
}

// linuxSynthTimestamp returns "" or a syslog clock prefix. sshd lines always
// use linuxSyslogPrefix instead (parser reads users from that shape).
// Uniquely named to avoid colliding with sibling synth helpers on merge.
func linuxSynthTimestamp(r *rand.Rand) string {
	if r.Intn(2) == 0 {
		return ""
	}
	return fmt.Sprintf("Sep 11 %02d:%02d:%02d ", r.Intn(24), r.Intn(60), r.Intn(60))
}

// linuxSyslogPrefix always returns a full "Sep 11 HH:MM:SS " stamp, matching
// the sshd shapes in samples/linux_iptables.log lines 6-7.
func linuxSyslogPrefix(r *rand.Rand) string {
	return fmt.Sprintf("Sep 11 %02d:%02d:%02d ", r.Intn(24), r.Intn(60), r.Intn(60))
}
