package utils

import (
	"bufio"
	"math/rand"
	"os"
	"time"
)

// GenerateCiscoASA returns n synthetic Cisco ASA syslog lines in the same
// shapes as samples/cisco_asa.log (IDs 302013/14/15/16/18/21, 305011/12,
// 106100/106023/106015, 725001/2, 110002, 313004, 305006, 402119, 602101).
// seed=0 uses time-based randomness; pass a fixed seed for reproducible tests.
//
// Lines are built by appending into a reused buffer (see synthfast.go) instead
// of fmt.Sprintf, and the Write* path streams through bufio rather than
// join-then-convert.
func GenerateCiscoASA(n int, seed int64) []string {
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
		synthASA(&g, r, i)
		out = append(out, g.str())
	}
	return out
}

// WriteCiscoASASamples writes n synthetic lines to path (one per line).
func WriteCiscoASASamples(path string, n int, seed int64) error {
	return writeLines(path, n, func(yield func(string)) {
		if seed == 0 {
			seed = time.Now().UnixNano()
		}
		r := rand.New(rand.NewSource(seed))
		var g lineBuf
		for i := 0; i < n; i++ {
			g.reset()
			synthASA(&g, r, i)
			yield(g.str())
		}
	})
}

// asaTS holds one synthetic syslog stamp. Drawn unconditionally (as the
// previous implementation did via synthTimestamp) so the random stream stays
// comparable; emitted only by the branches that carry a prefix.
type asaTS struct {
	mon, day, hh, mm, ss int
	style                int
}

// synthASA appends one synthetic Cisco ASA syslog line to g.
func synthASA(g *lineBuf, r *rand.Rand, i int) {
	ts := asaTS{
		mon:   r.Intn(12),
		day:   1 + r.Intn(28),
		hh:    r.Intn(24),
		mm:    r.Intn(60),
		ss:    r.Intn(60),
		style: r.Intn(3),
	}

	// Endpoint components are drawn once per line and reused by every branch so
	// a line never contradicts itself. The previous implementation formatted
	// them into intermediate strings up front for exactly this reason.
	//
	// inside: "192.168.<a>.<b>/<port>" with a=1+r.Intn(3), b=2+r.Intn(250).
	inA, inB, inPort := 1+r.Intn(3), 2+r.Intn(250), 1024+r.Intn(60000)
	outA, outB, outC, outD := 1+r.Intn(220), r.Intn(256), r.Intn(256), 2+r.Intn(250)
	outPort := asaPorts[r.Intn(6)]
	conn := 10000 + r.Intn(90000)
	bytes := 60 + r.Intn(200000)
	durH, durM, durS := r.Intn(2), r.Intn(60), r.Intn(60)
	proto := asaProtos[r.Intn(2)]

	// inIP writes "192.168.a.b"; inCIDR writes that plus "/port".
	inIP := func() { g.ip4(192, 168, inA, inB) }
	inCIDR := func() {
		inIP()
		g.c('/')
		g.i(inPort)
	}

	switch r.Intn(16) {
	case 0: // 302013 built outbound
		ts.write(g)
		g.s(" %ASA-6-302013: Built outbound ")
		g.s(proto)
		g.s(" connection ")
		g.i(conn)
		g.s(" for outside:")
		g.cidr(outA, outB, outC, outD, outPort)
		g.s(" (")
		g.cidr(outA, outB, outC, outD, outPort)
		g.s(") to inside:")
		inCIDR()
	case 1: // 302014 teardown
		ts.write(g)
		g.s(" %ASA-6-302014: Teardown ")
		g.s(proto)
		g.s(" connection ")
		g.i(conn)
		g.s(" for outside:")
		g.cidr(outA, outB, outC, outD, outPort)
		g.s(" to inside:")
		inCIDR()
		g.s(" duration ")
		g.writeDur(durH, durM, durS)
		g.s(" bytes ")
		g.i(bytes)
		g.c(' ')
		g.s(proto)
		g.s(" FINs")
	case 2: // 302015 built inbound UDP
		ts.write(g)
		g.s(" %ASA-6-302015: Built inbound UDP connection ")
		g.i(conn)
		g.s(" for outside:")
		g.cidr(outA, outB, outC, outD, outPort)
		g.s(" (")
		g.cidr(outA, outB, outC, outD, outPort)
		g.s(") to inside:")
		inCIDR()
		g.s(" (")
		inCIDR()
		g.s(")")
	case 3: // 302016 teardown UDP
		ts.write(g)
		g.s(" %ASA-6-302016: Teardown UDP connection ")
		g.i(conn)
		g.s(" for outside:")
		g.cidr(outA, outB, outC, outD, outPort)
		g.s(" to inside:")
		inCIDR()
		g.s(" duration ")
		g.writeDur(durH, durM, durS)
		g.s(" bytes ")
		g.i(60 + r.Intn(2000))
	case 4: // 302018 built outbound TCP
		ts.write(g)
		g.s(" %ASA-6-302018: Built outbound TCP connection ")
		g.i(conn)
		g.s(" for outside:")
		g.cidr(outA, outB, outC, outD, outPort)
		g.s(" (")
		g.cidr(outA, outB, outC, outD, outPort)
		g.s(") to inside:")
		inCIDR()
	case 5: // 302021 teardown ICMP
		ts.write(g)
		g.s(" %ASA-6-302021: Teardown ICMP connection ")
		g.i(conn)
		g.s(" for outside:8.8.8.8/0 to inside:")
		inCIDR()
		g.s(" duration ")
		g.writeDur(durH, durM, durS)
		g.s(" bytes ")
		g.i(28 + r.Intn(200))
	case 6: // 305011 dynamic translation created (no syslog prefix in source)
		g.s("%ASA-6-305011: Built dynamic TCP translation from inside:")
		inCIDR()
		g.s(" to outside:")
		g.cidr(outA, outB, outC, outD, outPort)
	case 7: // 305012 dynamic translation torn down
		g.s("%ASA-6-305012: Teardown dynamic TCP translation from inside:")
		inCIDR()
		g.s(" to outside:")
		g.cidr(outA, outB, outC, outD, outPort)
		g.s(" duration ")
		g.writeDur(durH, durM, durS)
	case 8: // 106023 access-group deny
		g.s("%ASA-4-106023: Deny tcp src inside:")
		inCIDR()
		g.s(" dst outside:")
		g.cidr(outA, outB, outC, outD, outPort)
		g.s(" by access-group inside_access_in")
	case 9: // 106100 access-list hit (inside/1.2.3.4(5678) form)
		g.s("%ASA-6-106100: access-list inside_access_in permitted tcp inside/")
		inIP()
		g.c('(')
		g.i(inPort)
		g.s(") -> outside/")
		g.ip4(outA, outB, outC, outD)
		g.c('(')
		g.i(outPort)
		g.s(") hit-cnt ")
		g.i(1 + r.Intn(50))
		g.s(" first hit")
	case 10: // 106015 deny no-connection
		g.s("%ASA-6-106015: Deny TCP (no connection) from ")
		inCIDR()
		g.s(" to ")
		g.ip4(outA, outB, outC, outD)
		g.c('/')
		g.i(1024 + r.Intn(60000))
		g.s(" flags ")
		g.s(asaFlags[r.Intn(3)])
		g.s(" on interface inside")
	case 11: // 725001 SSL handshake
		g.s("%ASA-6-725001: Starting SSL handshake with client outside:")
		g.cidr(outA, outB, outC, outD, outPort)
		g.s(" for TLSv1.2 session")
	case 12: // 313004 denied ICMP (host only, no port)
		g.s("%ASA-4-313004: Denied ICMP type=8, code=0 from ")
		inIP()
		g.s(" on interface inside")
	case 13: // 305006 portmap failure
		g.s("%ASA-3-305006: portmap translation creation failed for tcp src inside:")
		inCIDR()
		g.s(" dst outside:")
		g.cidr(outA, outB, outC, outD, outPort)
	case 14: // 402119 IPSEC bad SPI
		g.s("%ASA-4-402119: IPSEC: Received an ESP packet with invalid SPI from ")
		g.ip4(outA, outB, outC, outD)
		g.s(" to 203.0.113.")
		g.i(1 + r.Intn(250))
	default: // 110002 egress interface lookup failure
		ts.write(g)
		g.s(" %ASA-6-110002: Failed to locate egress interface for protocol tcp from inside:")
		inCIDR()
		g.s(" to outside:")
		g.cidr(outA, outB, outC, outD, outPort)
	}
}

// write appends the stamp in one of the two header styles seen in the samples,
// or nothing for style 2 (bare "%ASA-..." lines).
func (t asaTS) write(g *lineBuf) {
	switch t.style {
	case 0:
		g.s("<134>")
	case 1:
		g.s(monthAbbr[t.mon])
		g.c(' ')
		g.sp2(t.day)
		g.s(" 2024 ")
		g.p2(t.hh)
		g.c(':')
		g.p2(t.mm)
		g.c(':')
		g.p2(t.ss)
		g.s(" localhost CiscoASA[")
		g.i(100 + (t.mon*37+t.day*11+t.hh*7+t.mm*3+t.ss)%900)
		g.s("]:")
	}
}

// writeDur appends an "H:MM:SS" duration.
func (g *lineBuf) writeDur(h, m, s int) {
	g.i(h)
	g.c(':')
	g.p2(m)
	g.c(':')
	g.p2(s)
}

// writeLines streams generated lines to path via a buffered writer, replacing
// the strings.Join + []byte(...) pattern that materialised the corpus twice.
func writeLines(path string, n int, gen func(yield func(string))) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f, 1<<20)
	const chunk = 4096
	buf := make([]string, 0, chunk)
	flush := func() error {
		for _, ln := range buf {
			if _, err := w.WriteString(ln); err != nil {
				return err
			}
			if err := w.WriteByte('\n'); err != nil {
				return err
			}
		}
		buf = buf[:0]
		return nil
	}
	gen(func(ln string) {
		buf = append(buf, ln)
		if len(buf) == chunk {
			_ = flush()
		}
	})
	if err := flush(); err != nil {
		f.Close()
		return err
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
