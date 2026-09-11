package utils

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
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
	for i := 0; i < n; i++ {
		out = append(out, synthFortiGate(r, i))
	}
	return out
}

// WriteFortiGateSamples writes n synthetic lines to path (one per line).
func WriteFortiGateSamples(path string, n int, seed int64) error {
	lines := GenerateFortiGate(n, seed)
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func synthFortiGate(r *rand.Rand, i int) string {
	date, clock, epoch := synthFGTimestamp(r)
	srcIP := fmt.Sprintf("10.1.%d.%d", 100+r.Intn(3), 2+r.Intn(250))
	pubIP := fmt.Sprintf("%d.%d.%d.%d", 1+r.Intn(220), r.Intn(256), r.Intn(256), 2+r.Intn(250))
	dst := []string{"8.8.8.8", "1.1.1.1", "142.250.72.14", "93.184.216.34", pubIP}[r.Intn(5)]
	sport := 1024 + r.Intn(60000)
	session := 4400 + i
	bytes := 60 + r.Intn(200000)
	pkts := 1 + r.Intn(500)
	prefix := ""
	if r.Intn(4) == 0 {
		prefix = "<190>"
	}

	switch r.Intn(11) {
	case 0: // utm app-ctrl pass (samples line 1)
		dport := []int{80, 443}[r.Intn(2)]
		return fmt.Sprintf(`%sdate=%s time=%s logid="1059028704" type="utm" subtype="app-ctrl" eventtype="app-ctrl-all" level="information" vd="root" eventtime=%d appid=40568 srcip=%s dstip=%s srcport=%d dstport=%d srcintf="port10" srcintfrole="lan" dstintf="port9" dstintfrole="wan" proto=6 service="HTTPS" direction="outgoing" policyid=1 sessionid=%d applist="block-social.media" appcat="Web.Client" app="HTTPS.BROWSER" action="pass" hostname="www.example%d.com" incidentserialno=%d url="/" msg="Web.Client: HTTPS.BROWSER," apprisk="medium"`,
			prefix, date, clock, epoch, srcIP, dst, sport, dport, session, r.Intn(900)+100, 1962906680+i)
	case 1: // traffic forward accept (samples lines 2, 11-20)
		proto := []int{6, 6, 6, 17}[r.Intn(4)]
		dport := map[int]int{6: 443, 17: 53}[proto]
		app := map[int]string{6: "HTTPS", 17: "DNS"}[proto]
		return fmt.Sprintf(`%sdate=%s time=%s logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=%d srcip=%s dstip=%s srcport=%d dstport=%d srcintf="port10" dstintf="port9" proto=%d action="accept" policyid=1 sessionid=%d bytes=%d packets=%d app="%s"`,
			prefix, date, clock, epoch, srcIP, dst, sport, dport, proto, session, bytes, pkts, app)
	case 2: // traffic forward deny (samples line 3)
		return fmt.Sprintf(`%sdate=%s time=%s logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=%d srcip=%s dstip=%s srcport=%d dstport=443 srcintf="lan" dstintf="wan" proto=6 action="deny" policyid=0 sessionid=0 msg="Denied by forward policy"`,
			prefix, date, clock, epoch, srcIP, dst, sport)
	case 3: // utm virus blocked (samples line 4)
		return fmt.Sprintf(`%sdate=%s time=%s logid="0419016384" type="utm" subtype="virus" eventtype="infected" level="warning" vd="root" eventtime=%d srcip=%s dstip=%s srcport=%d dstport=80 proto=6 service="HTTP" action="blocked" filename="loader%d.exe" virus="EICAR-Test-Signature" msg="Virus detected"`,
			prefix, date, clock, epoch, srcIP, dst, sport, r.Intn(900)+100)
	case 4: // utm ips dropped (samples line 5)
		return fmt.Sprintf(`%sdate=%s time=%s logid="0422016384" type="utm" subtype="ips" eventtype="signature" level="alert" vd="root" eventtime=%d srcip=%s dstip=%s srcport=%d dstport=445 proto=6 service="SMB" action="dropped" attack="MS.SMB.Server.SMB1.Trans2.Secondary.Handling.Code.Execution" severity="high" msg="IPS signature match"`,
			prefix, date, clock, epoch, pubIP, srcIP, 1024+r.Intn(60000))
	case 5: // event system, no IPs (samples line 6)
		iface := []string{"port9", "port10", "lan"}[r.Intn(3)]
		return fmt.Sprintf(`%sdate=%s time=%s logid="0100040704" type="event" subtype="system" level="warning" vd="root" eventtime=%d logdesc="Interface status changed" interface="%s" status="up" msg="Interface %s link up"`,
			prefix, date, clock, epoch, iface, iface)
	case 6: // event user login (samples line 7)
		user := []string{"admin", "ops", "auditor"}[r.Intn(3)]
		return fmt.Sprintf(`%sdate=%s time=%s logid="0100040193" type="event" subtype="user" level="information" vd="root" eventtime=%d user="%s" action="login" status="success" srcip=%s msg="Administrator %s logged in successfully"`,
			prefix, date, clock, epoch, user, srcIP, user)
	case 7: // event vpn ssl-login (samples line 8)
		return fmt.Sprintf(`%sdate=%s time=%s logid="0100040802" type="event" subtype="vpn" level="information" vd="root" eventtime=%d user="vpnuser%d" action="ssl-login" status="success" srcip=%s dstip=%s msg="SSL VPN user connected"`,
			prefix, date, clock, epoch, r.Intn(90)+10, pubIP, srcIP)
	case 8: // traffic local accept (samples line 9)
		return fmt.Sprintf(`%sdate=%s time=%s logid="0000000013" type="traffic" subtype="local" level="notice" vd="root" eventtime=%d srcip=%s dstip=10.1.100.1 srcport=22 dstport=22 proto=6 action="accept" msg="SSH management access"`,
			prefix, date, clock, epoch, srcIP)
	default: // utm webfilter blocked (samples line 10)
		return fmt.Sprintf(`%sdate=%s time=%s logid="0317016384" type="utm" subtype="webfilter" eventtype="urlfilter" level="warning" vd="root" eventtime=%d srcip=%s dstip=93.184.216.34 srcport=%d dstport=80 proto=6 service="HTTP" action="blocked" hostname="example-blocked%d.com" url="/" catdesc="Malicious Websites" msg="URL blocked by webfilter"`,
			prefix, date, clock, epoch, srcIP, sport, r.Intn(900)+100)
	}
}

// synthFGTimestamp returns matching date, clock, and epoch seconds so the
// generated date/time/eventtime triple stays consistent for fortiGateTime.
func synthFGTimestamp(r *rand.Rand) (date, clock string, epoch int64) {
	t := time.Date(2019, 5, 15+r.Intn(3), r.Intn(24), r.Intn(60), r.Intn(60), 0, time.UTC)
	return t.Format("2006-01-02"), t.Format("15:04:05"), t.Unix()
}
