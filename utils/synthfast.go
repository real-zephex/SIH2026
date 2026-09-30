package utils

import (
	"strconv"
)

// Shared fast-formatting helpers for the synthetic log generators.
//
// Before this existed every generator line cost ~10-16 allocations and
// ~1.4-4.1 us, dominated by:
//   - fmt.Sprintf (reflection-driven boxing of every argument),
//   - map and slice literals constructed *inside* the per-line switch
//     (e.g. map[int]string{6: "HTTPS", 17: "DNS"}[proto]),
//   - time.Date + time.Format for timestamps that are just numbers,
//   - strings.Join(lines, "\n") followed by []byte(...) in the Write* helpers,
//     which materialised the whole corpus twice in memory.
//
// lineBuf is reused for the whole generation loop, so each line now costs one
// allocation: the final string.

// lineBuf is a reusable scratch buffer for building one synthetic log line.
type lineBuf struct{ b []byte }

func (g *lineBuf) reset() { g.b = g.b[:0] }

// str returns the accumulated bytes as a string (one allocation).
func (g *lineBuf) str() string { return string(g.b) }

// len reports the accumulated length without allocating.
func (g *lineBuf) len() int { return len(g.b) }

// s appends a string.
func (g *lineBuf) s(v string) { g.b = append(g.b, v...) }

// c appends one byte.
func (g *lineBuf) c(v byte) { g.b = append(g.b, v) }

// i appends a base-10 int.
func (g *lineBuf) i(v int) { g.b = strconv.AppendInt(g.b, int64(v), 10) }

// i64 appends a base-10 int64.
func (g *lineBuf) i64(v int64) { g.b = strconv.AppendInt(g.b, v, 10) }

// p2 appends a zero-padded 2-digit value (fmt %02d).
func (g *lineBuf) p2(v int) { g.b = appendPadded(g.b, v, 2, '0') }

// p3 appends a zero-padded 3-digit value (fmt %03d).
func (g *lineBuf) p3(v int) { g.b = appendPadded(g.b, v, 3, '0') }

// p4 appends a zero-padded 4-digit value (fmt %04d).
func (g *lineBuf) p4(v int) { g.b = appendPadded(g.b, v, 4, '0') }

// p6 appends a zero-padded 6-digit value (fmt %06d).
func (g *lineBuf) p6(v int) { g.b = appendPadded(g.b, v, 6, '0') }

// sp2 appends a space-padded value in width 2 (fmt %2d).
func (g *lineBuf) sp2(v int) { g.b = appendPadded(g.b, v, 2, ' ') }

// ip4 appends a dotted-quad address.
func (g *lineBuf) ip4(a, b, c, d int) {
	g.b = strconv.AppendInt(g.b, int64(a), 10)
	g.b = append(g.b, '.')
	g.b = strconv.AppendInt(g.b, int64(b), 10)
	g.b = append(g.b, '.')
	g.b = strconv.AppendInt(g.b, int64(c), 10)
	g.b = append(g.b, '.')
	g.b = strconv.AppendInt(g.b, int64(d), 10)
}

// cidr appends "<a.b.c.d>/<port>".
func (g *lineBuf) cidr(a, b, c, d, port int) {
	g.ip4(a, b, c, d)
	g.c('/')
	g.i(port)
}

// appendPadded appends v in base 10 right-aligned to width w, left-filled
// with pad. Replaces fmt's %0Nd / %Nd verbs without the reflection cost.
func appendPadded(dst []byte, v, w int, pad byte) []byte {
	var tmp [24]byte
	n := len(tmp)
	neg := v < 0
	if neg {
		v = -v
	}
	if v == 0 {
		n--
		tmp[n] = '0'
	}
	for v > 0 {
		n--
		tmp[n] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		n--
		tmp[n] = '-'
	}
	for i := len(tmp) - n; i < w; i++ {
		dst = append(dst, pad)
	}
	return append(dst, tmp[n:]...)
}

// monthAbbr is the syslog month table (index 0 = January).
var monthAbbr = [12]string{
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
}

// Port pools, hoisted to package scope. These were previously re-created as
// slice/map literals on every generated line.
var (
	asaPorts    = [6]int{22, 23, 53, 80, 443, 8443}
	asaProtos   = [2]string{"TCP", "UDP"}
	asaFlags    = [3]string{"ACK", "SYN", "RST"}
	fgDst       = [...]string{"8.8.8.8", "1.1.1.1", "142.250.72.14", "93.184.216.34"}
	fgIfaces    = [3]string{"port9", "port10", "lan"}
	fgUsers     = [3]string{"admin", "ops", "auditor"}
	linuxVerds  = [2]string{"wan-lan-default-D", "lan-wan-accept-A"}
	linuxDst    = [3]string{"10.0.0.5", "10.4.0.5", "172.18.0.5"}
	linuxDports = [6]int{22, 22, 22, 80, 443, 53}
	suriTCPPort = [5]int{22, 80, 443, 445, 139}
	suriUDPPort = [3]int{53, 137, 500}
	suriProtos  = [4]string{"TCP", "TCP", "TCP", "UDP"}
	suriActions = [3]string{"allowed", "allowed", "blocked"}
	suriTypes   = [4]string{"http", "dns", "flow", "tls"}
)

// pick returns a pseudo-random element of a string array without allocating.
func pickStr(arr []string, n int) string { return arr[n%len(arr)] }

// pickInt returns a pseudo-random element of an int array without allocating.
func pickInt(arr []int, n int) int { return arr[n%len(arr)] }

// fgProtoPort maps a protocol number to its port and app name without a map.
func fgProtoPort(proto int) (port int, app string) {
	if proto == 17 {
		return 53, "DNS"
	}
	return 443, "HTTPS"
}
