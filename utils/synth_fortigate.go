package utils

import (
	"math/rand"
	"time"
)

// GenerateFortiGate returns n synthetic FortiGate key=value log lines in the
// same shapes as samples/fortigate.log:
// traffic forward/local (accept/deny), utm app-ctrl/virus/ips/webfilter
// (pass/blocked/dropped), event system/user/vpn (no-IP safe).
// Every line carries date + time + eventtime so Parse timestamps resolve.
// seed=0 uses time-based randomness; pass a fixed seed for reproducible tests.
func GenerateFortiGate(n int, seed int64) []string {
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
		synthFortiGate(&g, r, i)
		out = append(out, g.str())
	}
	return out
}

// WriteFortiGateSamples writes n synthetic lines to path (one per line).
func WriteFortiGateSamples(path string, n int, seed int64) error {
	return writeLines(path, n, func(yield func(string)) {
		if seed == 0 {
			seed = time.Now().UnixNano()
		}
		r := rand.New(rand.NewSource(seed))
		var g lineBuf
		for i := 0; i < n; i++ {
			g.reset()
			synthFortiGate(&g, r, i)
			yield(g.str())
		}
	})
}

// synthFortiGate appends one synthetic FortiGate key=value line to g.
func synthFortiGate(g *lineBuf, r *rand.Rand, i int) {
	// date/time/eventtime must stay mutually consistent, so the epoch is
	// derived from the same y/m/d/h/m/s that get rendered. The previous
	// implementation built a time.Time and called Format twice per line.
	year, month, day := 2019, time.May, 15+r.Intn(3)
	hour, minute, sec := r.Intn(24), r.Intn(60), r.Intn(60)
	epoch := time.Date(year, month, day, hour, minute, sec, 0, time.UTC).Unix()

	srcA, srcB, srcC := 10, 1, 100+r.Intn(3)
	srcD := 2 + r.Intn(250)
	pubA, pubB, pubC, pubD := 1+r.Intn(220), r.Intn(256), r.Intn(256), 2+r.Intn(250)
	dstIdx := r.Intn(4)
	dst := fgDst[dstIdx]
	if dstIdx == 4 { // the 5th slot is the random public IP
		dst = ""
	}
	sport := 1024 + r.Intn(60000)
	session := 4400 + i
	bytes := 60 + r.Intn(200000)
	pkts := 1 + r.Intn(500)

	// fgHead writes the "<190>"-optional prefix plus the date/time/eventtime
	// triple that every FortiGate line starts with.
	fgHead := func() {
		if r.Intn(4) == 0 {
			g.s("<190>")
		}
		g.s("date=")
		g.i(year)
		g.c('-')
		g.p2(int(month))
		g.c('-')
		g.p2(day)
		g.s(" time=")
		g.p2(hour)
		g.c(':')
		g.p2(minute)
		g.c(':')
		g.p2(sec)
		g.s(" eventtime=")
		g.i64(epoch)
		g.c(' ')
	}
	// dstIP writes the resolved destination (public IP for slot 4).
	dstIP := func() {
		if dst == "" {
			g.ip4(pubA, pubB, pubC, pubD)
			return
		}
		g.s(dst)
	}

	switch r.Intn(11) {
	case 0: // utm app-ctrl pass
		dport := 80
		if r.Intn(2) == 0 {
			dport = 443
		}
		fgHead()
		g.s(`logid="1059028704" type="utm" subtype="app-ctrl" eventtype="app-ctrl-all" level="information" vd="root" appid=40568 srcip=`)
		g.ip4(srcA, srcB, srcC, srcD)
		g.s(" dstip=")
		dstIP()
		g.s(" srcport=")
		g.i(sport)
		g.s(" dstport=")
		g.i(dport)
		g.s(` srcintf="port10" srcintfrole="lan" dstintf="port9" dstintfrole="wan" proto=6 service="HTTPS" direction="outgoing" policyid=1 sessionid=`)
		g.i(session)
		g.s(` applist="block-social.media" appcat="Web.Client" app="HTTPS.BROWSER" action="pass" hostname="www.example`)
		g.i(r.Intn(900) + 100)
		g.s(`.com" incidentserialno=`)
		g.i(1962906680 + i)
		g.s(` url="/" msg="Web.Client: HTTPS.BROWSER," apprisk="medium"`)
	case 1: // traffic forward accept
		proto := 6
		if r.Intn(4) == 3 {
			proto = 17
		}
		dport, app := fgProtoPort(proto)
		fgHead()
		g.s(`logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=`)
		g.ip4(srcA, srcB, srcC, srcD)
		g.s(" dstip=")
		dstIP()
		g.s(" srcport=")
		g.i(sport)
		g.s(" dstport=")
		g.i(dport)
		g.s(` srcintf="port10" dstintf="port9" proto=`)
		g.i(proto)
		g.s(` action="accept" policyid=1 sessionid=`)
		g.i(session)
		g.s(" bytes=")
		g.i(bytes)
		g.s(" packets=")
		g.i(pkts)
		g.s(` app="`)
		g.s(app)
		g.s(`"`)
	case 2: // traffic forward deny
		fgHead()
		g.s(`logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=`)
		g.ip4(srcA, srcB, srcC, srcD)
		g.s(" dstip=")
		dstIP()
		g.s(" srcport=")
		g.i(sport)
		g.s(` dstport=443 srcintf="lan" dstintf="wan" proto=6 action="deny" policyid=0 sessionid=0 msg="Denied by forward policy"`)
	case 3: // utm virus blocked
		fgHead()
		g.s(`logid="0419016384" type="utm" subtype="virus" eventtype="infected" level="warning" vd="root" srcip=`)
		g.ip4(srcA, srcB, srcC, srcD)
		g.s(" dstip=")
		dstIP()
		g.s(" srcport=")
		g.i(sport)
		g.s(` dstport=80 proto=6 service="HTTP" action="blocked" filename="loader`)
		g.i(r.Intn(900) + 100)
		g.s(`.exe" virus="EICAR-Test-Signature" msg="Virus detected"`)
	case 4: // utm ips dropped (attacker-facing, so src is the public IP)
		fgHead()
		g.s(`logid="0422016384" type="utm" subtype="ips" eventtype="signature" level="alert" vd="root" srcip=`)
		g.ip4(pubA, pubB, pubC, pubD)
		g.s(" dstip=")
		g.ip4(srcA, srcB, srcC, srcD)
		g.s(" srcport=")
		g.i(1024 + r.Intn(60000))
		g.s(` dstport=445 proto=6 service="SMB" action="dropped" attack="MS.SMB.Server.SMB1.Trans2.Secondary.Handling.Code.Execution" severity="high" msg="IPS signature match"`)
	case 5: // event system, no IPs
		iface := fgIfaces[r.Intn(3)]
		fgHead()
		g.s(`logid="0100040704" type="event" subtype="system" level="warning" vd="root" logdesc="Interface status changed" interface="`)
		g.s(iface)
		g.s(`" status="up" msg="Interface `)
		g.s(iface)
		g.s(` link up"`)
	case 6: // event user login
		user := fgUsers[r.Intn(3)]
		fgHead()
		g.s(`logid="0100040193" type="event" subtype="user" level="information" vd="root" user="`)
		g.s(user)
		g.s(`" action="login" status="success" srcip=`)
		g.ip4(srcA, srcB, srcC, srcD)
		g.s(` msg="Administrator `)
		g.s(user)
		g.s(` logged in successfully"`)
	case 7: // event vpn ssl-login
		fgHead()
		g.s(`logid="0100040802" type="event" subtype="vpn" level="information" vd="root" user="vpnuser`)
		g.i(r.Intn(90) + 10)
		g.s(`" action="ssl-login" status="success" srcip=`)
		g.ip4(srcA, srcB, srcC, srcD)
		g.s(" dstip=")
		g.ip4(pubA, pubB, pubC, pubD)
		g.s(` msg="SSL VPN user connected"`)
	case 8: // traffic local accept
		fgHead()
		g.s(`logid="0000000013" type="traffic" subtype="local" level="notice" vd="root" srcip=`)
		g.ip4(srcA, srcB, srcC, srcD)
		g.s(` dstip=10.1.100.1 srcport=22 dstport=22 proto=6 action="accept" msg="SSH management access"`)
	default: // utm webfilter blocked
		fgHead()
		g.s(`logid="0317016384" type="utm" subtype="webfilter" eventtype="urlfilter" level="warning" vd="root" srcip=`)
		g.ip4(srcA, srcB, srcC, srcD)
		g.s(` dstip=93.184.216.34 srcport=`)
		g.i(sport)
		g.s(` dstport=80 proto=6 service="HTTP" action="blocked" hostname="example-blocked`)
		g.i(r.Intn(900) + 100)
		g.s(`.com" url="/" catdesc="Malicious Websites" msg="URL blocked by webfilter"`)
	}
}
