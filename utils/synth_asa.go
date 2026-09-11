package utils

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"
)

// GenerateCiscoASA returns n synthetic Cisco ASA syslog lines in the same
// shapes as samples/cisco_asa.log (IDs 302013/14/15/16/18/21, 305011/12,
// 106100/106023/106015, 725001/2, 110002, 313004, 305006, 402119, 602101).
// seed=0 uses time-based randomness; pass a fixed seed for reproducible tests.
func GenerateCiscoASA(n int, seed int64) []string {
	if n <= 0 {
		return nil
	}
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	r := rand.New(rand.NewSource(seed))
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, synthASA(r, i))
	}
	return out
}

// WriteCiscoASASamples writes n synthetic lines to path (one per line).
func WriteCiscoASASamples(path string, n int, seed int64) error {
	lines := GenerateCiscoASA(n, seed)
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func synthASA(r *rand.Rand, i int) string {
	ts := synthTimestamp(r)
	inside := fmt.Sprintf("192.168.%d.%d/%d", 1+r.Intn(3), 2+r.Intn(250), 1024+r.Intn(60000))
	insideNoPort := strings.Split(inside, "/")[0]
	outsideIP := fmt.Sprintf("%d.%d.%d.%d", 1+r.Intn(220), r.Intn(256), r.Intn(256), 2+r.Intn(250))
	outside := fmt.Sprintf("%s/%d", outsideIP, []int{22, 23, 53, 80, 443, 8443}[r.Intn(6)])
	conn := 10000 + r.Intn(90000)
	bytes := 60 + r.Intn(200000)
	dur := fmt.Sprintf("%d:%02d:%02d", r.Intn(2), r.Intn(60), r.Intn(60))
	protos := []string{"TCP", "UDP"}
	proto := protos[r.Intn(len(protos))]

	switch r.Intn(16) {
	case 0:
		return fmt.Sprintf("%s %%ASA-6-302013: Built outbound %s connection %d for outside:%s (%s) to inside:%s", ts, proto, conn, outside, outside, inside)
	case 1:
		return fmt.Sprintf("%s %%ASA-6-302014: Teardown %s connection %d for outside:%s to inside:%s duration %s bytes %d %s FINs", ts, proto, conn, outside, inside, dur, bytes, proto)
	case 2:
		return fmt.Sprintf("%s %%ASA-6-302015: Built inbound UDP connection %d for outside:%s (%s) to inside:%s (%s)", ts, conn, outside, outside, inside, inside)
	case 3:
		return fmt.Sprintf("%s %%ASA-6-302016: Teardown UDP connection %d for outside:%s to inside:%s duration %s bytes %d", ts, conn, outside, inside, dur, 60+r.Intn(2000))
	case 4:
		return fmt.Sprintf("%s %%ASA-6-302018: Built outbound TCP connection %d for outside:%s (%s) to inside:%s", ts, conn, outside, outside, inside)
	case 5:
		return fmt.Sprintf("%s %%ASA-6-302021: Teardown ICMP connection %d for outside:8.8.8.8/0 to inside:%s duration %s bytes %d", ts, conn, inside, dur, 28+r.Intn(200))
	case 6:
		return fmt.Sprintf("%%ASA-6-305011: Built dynamic TCP translation from inside:%s to outside:%s", inside, outside)
	case 7:
		return fmt.Sprintf("%%ASA-6-305012: Teardown dynamic TCP translation from inside:%s to outside:%s duration %s", inside, outside, dur)
	case 8:
		return fmt.Sprintf("%%ASA-4-106023: Deny tcp src inside:%s dst outside:%s by access-group inside_access_in", inside, outside)
	case 9:
		return fmt.Sprintf("%%ASA-6-106100: access-list inside_access_in permitted tcp inside/%s -> outside/%s hit-cnt %d first hit", strings.Replace(inside, "/", "(", 1)+")", strings.Replace(outside, "/", "(", 1)+")", 1+r.Intn(50))
	case 10:
		return fmt.Sprintf("%%ASA-6-106015: Deny TCP (no connection) from %s to %s flags %s on interface inside", inside, outsideIP+"/"+fmt.Sprint(1024+r.Intn(60000)), []string{"ACK", "SYN", "RST"}[r.Intn(3)])
	case 11:
		return fmt.Sprintf("%%ASA-6-725001: Starting SSL handshake with client outside:%s for TLSv1.2 session", outside)
	case 12:
		return fmt.Sprintf("%%ASA-4-313004: Denied ICMP type=8, code=0 from %s on interface inside", insideNoPort)
	case 13:
		return fmt.Sprintf("%%ASA-3-305006: portmap translation creation failed for tcp src inside:%s dst outside:%s", inside, outside)
	case 14:
		return fmt.Sprintf("%%ASA-4-402119: IPSEC: Received an ESP packet with invalid SPI from %s to %s", outsideIP, fmt.Sprintf("203.0.113.%d", 1+r.Intn(250)))
	default:
		return fmt.Sprintf("%s %%ASA-6-110002: Failed to locate egress interface for protocol tcp from inside:%s to outside:%s", ts, inside, outside)
	}
}

func synthTimestamp(r *rand.Rand) string {
	// Mix the two header styles seen in samples: with and without syslog prefix.
	t := time.Date(2024, time.Month(1+r.Intn(12)), 1+r.Intn(28), r.Intn(24), r.Intn(60), r.Intn(60), 0, time.UTC)
	months := []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	base := fmt.Sprintf("%s %2d 2024 %02d:%02d:%02d", months[int(t.Month())-1], t.Day(), t.Hour(), t.Minute(), t.Second())
	switch r.Intn(3) {
	case 0:
		return fmt.Sprintf("<134>%s:", base)
	case 1:
		return fmt.Sprintf("%s localhost CiscoASA[%d]:", base, 100+r.Intn(900))
	default:
		return ""
	}
}
