package utils

import (
	"math/rand"
	"time"
)

// GenerateSuricata returns n synthetic Suricata EVE JSONLines in the same
// shapes as samples/suricata_eve.json: mostly "alert" events across the ET
// categories seen in the samples, plus "http"/"dns"/"flow"/"tls" traffic
// events to exercise the parser's 4001 NetworkActivity path.
// seed=0 uses time-based randomness; pass a fixed seed for reproducible tests.
//
// The JSON is now emitted directly rather than through encoding/json.
// json.Marshal reflected over a nested struct graph cost ~4057 ns and ~10.5
// allocations per line, making this the slowest generator by 3-4x. Emitting the
// bytes by hand also lets us match real EVE output more closely: absent objects
// ("http" on a dns event) are now omitted instead of serialised as {}.
func GenerateSuricata(n int, seed int64) []string {
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
		synthSuricataJSON(&g, r, i)
		out = append(out, g.str())
	}
	return out
}

// WriteSuricataSamples writes n synthetic EVE JSONLines to path.
func WriteSuricataSamples(path string, n int, seed int64) error {
	return writeLines(path, n, func(yield func(string)) {
		if seed == 0 {
			seed = time.Now().UnixNano()
		}
		r := rand.New(rand.NewSource(seed))
		var g lineBuf
		for i := 0; i < n; i++ {
			g.reset()
			synthSuricataJSON(&g, r, i)
			yield(g.str())
		}
	})
}

// suricataSig is one ET signature template.
type suricataSig struct {
	sig      string
	category string
	severity int
	sid      int
}

var suricataSigs = [...]suricataSig{
	{"ET SCAN Potential SSH Scan", "Attempted Information Leak", 2, 2001219},
	{"ET SCAN Behavioral Unusual Port 445 traffic Potential Scan or Infection", "Misc activity", 3, 2001569},
	{"ET SCAN Behavioral Unusual Port 139 traffic Potential Scan or Infection", "Misc activity", 3, 2001579},
	{"ET MALWARE BTGrab.com Spyware Downloading Ads", "A Network Trojan was detected", 1, 2001999},
	{"ET TROJAN Possible Zeus Gameover Response", "A Network Trojan was detected", 1, 2018312},
	{"ET POLICY Outbound Frequent Tor Connection", "Potential Corporate Privacy Violation", 2, 2017930},
	{"ET POLICY DNS Query for TOR Hidden Domain", "Potential Corporate Privacy Violation", 2, 2017931},
	{"ET EXPLOIT Possible CVE-2017-0144 SMB RCE", "Attempted Administrator Privilege Gain", 1, 2024218},
	{"ET WEB_SERVER Suspicious POST to Login Endpoint", "Attempted Administrator Privilege Gain", 2, 2017764},
	{"ET INFO Successful SSH Login Bruteforced", "Successful Administrator Privilege Gain", 1, 2006546},
}

// jstr appends a JSON string literal. The generator only ever emits
// signature/hostname/UA values from fixed ASCII tables with no characters that
// need escaping, so a straight copy is sufficient and allocation-free.
func (g *lineBuf) jstr(v string) {
	g.c('"')
	g.s(v)
	g.c('"')
}

// synthSuricataJSON appends one synthetic EVE JSON line to g.
func synthSuricataJSON(g *lineBuf, r *rand.Rand, i int) {
	// Timestamp: 2018-03-2X, MDT (-0600), microsecond precision.
	mon, day := 3, 20+r.Intn(8)
	hour, minute, sec := r.Intn(24), r.Intn(60), r.Intn(60)
	micro := r.Intn(1e6)

	srcA, srcB, srcC, srcD := 10, r.Intn(200)+10, r.Intn(250)+2, r.Intn(250)+2
	dstA, dstB, dstC, dstD := 10, 40+r.Intn(10), r.Intn(250)+2, r.Intn(250)+2
	proto := suriProtos[r.Intn(4)]
	sport := 1024 + r.Intn(60000)
	var dport int
	if proto == "TCP" {
		dport = suriTCPPort[r.Intn(5)]
	} else {
		dport = suriUDPPort[r.Intn(3)]
	}
	flowID := r.Int63n(900000000000000) + 100000
	pcapCnt := 100000 + i*37 + r.Intn(500)

	pktsToServer := 1 + r.Intn(8)
	pktsToClient := r.Intn(pktsToServer + 1)
	bytesToServer := 60 + r.Intn(4000)
	bytesToClient := r.Intn(8000)

	isAlert := r.Intn(4) < 3
	eventType := "alert"
	if !isAlert {
		eventType = suriTypes[r.Intn(4)]
	}
	appProto := ""
	if isAlert {
		if eventType == "alert" && r.Intn(3) == 0 {
			appProto = "http"
		}
	} else {
		switch eventType {
		case "http", "dns", "tls":
			appProto = eventType
		}
	}
	withHTTP := appProto == "http"

	g.c('{')
	g.s(`"timestamp":"`)
	g.p4(yearSuricata)
	g.c('-')
	g.p2(mon)
	g.c('-')
	g.p2(day)
	g.s(`T`)
	g.p2(hour)
	g.c(':')
	g.p2(minute)
	g.c(':')
	g.p2(sec)
	g.c('.')
	g.p6(micro)
	g.s(`-0600","flow_id":`)
	g.i64(flowID)
	g.s(`,"pcap_cnt":`)
	g.i64(int64(pcapCnt))
	g.s(`,"event_type":"`)
	g.s(eventType)
	g.s(`","src_ip":"`)
	g.ip4(srcA, srcB, srcC, srcD)
	g.s(`","src_port":`)
	g.i(sport)
	g.s(`,"dest_ip":"`)
	g.ip4(dstA, dstB, dstC, dstD)
	g.s(`","dest_port":`)
	g.i(dport)
	g.s(`,"proto":"`)
	g.s(proto)
	g.c('"')
	if appProto != "" {
		g.s(`,"app_proto":"`)
		g.s(appProto)
		g.c('"')
	}

	if isAlert {
		s := suricataSigs[r.Intn(len(suricataSigs))]
		g.s(`,"alert":{"action":"`)
		g.s(suriActions[r.Intn(3)])
		g.s(`","gid":1,"signature_id":`)
		g.i(s.sid)
		g.s(`,"rev":`)
		g.i(1 + r.Intn(20))
		g.s(`,"signature":`)
		g.jstr(s.sig)
		g.s(`,"category":`)
		g.jstr(s.category)
		g.s(`,"severity":`)
		g.i(s.severity)
		g.c('}')
	}

	g.s(`,"flow":{"pkts_toserver":`)
	g.i(pktsToServer)
	g.s(`,"pkts_toclient":`)
	g.i(pktsToClient)
	g.s(`,"bytes_toserver":`)
	g.i(bytesToServer)
	g.s(`,"bytes_toclient":`)
	g.i(bytesToClient)
	g.c('}')

	if withHTTP {
		g.s(`,"http":{"hostname":"evil`)
		g.i(r.Intn(900) + 100)
		g.s(`.example.com","url":"/loader.exe","http_user_agent":"Mozilla/5.0","http_method":"GET","status":200}`)
	}

	g.c('}')
}

// yearSuricata is the fixed year used by the synthetic EVE timestamps, chosen
// to match the WRCCDC-2018 captures the samples were derived from.
const yearSuricata = 2018
