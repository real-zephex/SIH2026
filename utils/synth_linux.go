package utils

import (
	"math/rand"
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
	var g lineBuf
	for i := 0; i < n; i++ {
		g.reset()
		synthLinux(&g, r, i)
		out = append(out, g.str())
	}
	return out
}

// WriteLinuxSamples writes n synthetic lines to path (one per line).
func WriteLinuxSamples(path string, n int, seed int64) error {
	return writeLines(path, n, func(yield func(string)) {
		if seed == 0 {
			seed = time.Now().UnixNano()
		}
		r := rand.New(rand.NewSource(seed))
		var g lineBuf
		for i := 0; i < n; i++ {
			g.reset()
			synthLinux(&g, r, i)
			yield(g.str())
		}
	})
}

var linuxUsers = [6]string{"admin", "root", "zephex", "ops", "deploy", "ubuntu"}

// linuxMAC is the bridge MAC seen in most sample netfilter lines.
const linuxMAC = "MAC=90:10:20:76:8d:20:90:10:65:29:b6:2a:08:00 "

// writeClock appends a "Sep 11 HH:MM:SS " syslog prefix.
func (g *lineBuf) writeClock(h, m, s int) {
	g.s("Sep 11 ")
	g.p2(h)
	g.c(':')
	g.p2(m)
	g.c(':')
	g.p2(s)
	g.c(' ')
}

// synthLinux appends one synthetic Linux log line to g.
func synthLinux(g *lineBuf, r *rand.Rand, i int) {
	// Attacker-style public source vs internal source mix.
	var srcA, srcB, srcC, srcD int
	if r.Intn(4) == 0 {
		srcA, srcB, srcC, srcD = 192, 168, 1+r.Intn(3), 2+r.Intn(250)
	} else {
		srcA, srcB, srcC, srcD = 45, 148, r.Intn(30)+10, 2+r.Intn(250)
	}
	dst := linuxDst[r.Intn(3)]
	sport := 1024 + r.Intn(60000)
	dport := linuxDports[r.Intn(6)]
	ttl := 52 + r.Intn(13)
	id := 10000 + r.Intn(50000)

	mac := linuxMAC
	if r.Intn(3) == 0 {
		mac = ""
	}
	// ts is drawn unconditionally (as before) but only emitted by the
	// netfilter shapes that carry a syslog stamp.
	tsH, tsM, tsS, hasTS := r.Intn(24), r.Intn(60), r.Intn(60), r.Intn(2) == 0
	writeTS := func() {
		if hasTS {
			g.writeClock(tsH, tsM, tsS)
		}
	}

	// srcIP/dstIP write the endpoint pair.
	srcIP := func() { g.ip4(srcA, srcB, srcC, srcD) }

	switch r.Intn(8) {
	case 0, 1: // [UFW BLOCK] TCP (most common, samples lines 2, 8, 11-20)
		writeTS()
		g.s("myhost kernel: [UFW BLOCK] IN=eth0 OUT= ")
		g.s(mac)
		g.s("SRC=")
		srcIP()
		g.s(" DST=")
		g.s(dst)
		g.s(" LEN=60 TOS=0x00 PREC=0x00 TTL=")
		g.i(ttl)
		g.s(" ID=")
		g.i(id + i)
		g.s(" DF PROTO=TCP SPT=")
		g.i(sport)
		g.s(" DPT=")
		g.i(dport)
		g.s(" WINDOW=64240 RES=0x00 SYN URGP=0")
	case 2: // [UFW ALLOW]
		writeTS()
		g.s("myhost kernel: [UFW ALLOW] IN=eth0 OUT= ")
		g.s(mac)
		g.s("SRC=")
		srcIP()
		g.s(" DST=")
		g.s(dst)
		if r.Intn(2) == 0 {
			g.s(" LEN=84 TOS=0x00 PREC=0x00 TTL=64 ID=")
			g.i(id + i)
			g.s(" PROTO=ICMP TYPE=8 CODE=0 ID=1 SEQ=")
			g.i(r.Intn(100))
			return
		}
		g.s(" LEN=52 TOS=0x00 TTL=64 ID=")
		g.i(id + i)
		g.s(" PROTO=TCP SPT=")
		g.i(sport)
		g.s(" DPT=22 WINDOW=2853 RES=0x00 ACK URGP=0")
	case 3: // [IPTABLES-DROP]
		writeTS()
		g.s("myhost kernel: [IPTABLES-DROP] IN=eth0 OUT= ")
		g.s(mac)
		g.s("SRC=")
		srcIP()
		g.s(" DST=")
		g.s(dst)
		g.s(" LEN=52 TOS=0x00 PREC=0x00 TTL=")
		g.i(ttl)
		g.s(" ID=")
		g.i(id + i)
		g.s(" DF PROTO=TCP SPT=")
		g.i(sport)
		g.s(" DPT=443 WINDOW=2853 RES=0x00 ACK URGP=0")
	case 4: // [NEW SSH]
		writeTS()
		g.s("myhost kernel: [NEW SSH] IN=eth0 OUT= SRC=")
		srcIP()
		g.s(" DST=")
		g.s(dst)
		g.s(" LEN=60 PROTO=TCP SPT=")
		g.i(sport)
		g.s(" DPT=22 SYN URGP=0")
	case 5: // sshd Failed password
		user := linuxUsers[r.Intn(6)]
		g.writeClock(r.Intn(24), r.Intn(60), r.Intn(60))
		g.s("myhost sshd[")
		g.i(1000 + r.Intn(9000))
		if r.Intn(2) == 0 {
			g.s("]: Failed password for invalid user ")
		} else {
			g.s("]: Failed password for ")
		}
		g.s(user)
		g.s(" from ")
		srcIP()
		g.s(" port ")
		g.i(sport)
		g.s(" ssh2")
	case 6: // sshd Accepted password
		user := linuxUsers[r.Intn(6)]
		g.writeClock(r.Intn(24), r.Intn(60), r.Intn(60))
		g.s("myhost sshd[")
		g.i(1000 + r.Intn(9000))
		g.s("]: Accepted password for ")
		g.s(user)
		g.s(" from ")
		srcIP()
		g.s(" port ")
		g.i(sport)
		g.s(" ssh2")
	default: // generic filter verdict line (samples line 1 style)
		verdict := linuxVerds[r.Intn(2)]
		writeTS()
		g.s("Hostname kernel: [")
		g.s(verdict)
		g.s("]IN=eth0 OUT= ")
		g.s(mac)
		g.s("SRC=")
		srcIP()
		g.s(" DST=")
		g.s(dst)
		g.s(" LEN=52 TOS=0x00 PREC=0x00 TTL=")
		g.i(ttl)
		g.s(" ID=")
		g.i(id + i)
		g.s(" DF PROTO=TCP SPT=")
		g.i(sport)
		g.s(" DPT=443 WINDOW=2853 RES=0x00 ACK URGP=0")
	}
}
