package portdiscovery

import (
	"bytes"
	"fmt"
	"net"
)

// ExpandIPRange returns every IPv4 address from start to end, inclusive, in
// ascending order. Each returned address is an independent slice, so callers can
// keep them (for example in a ScanTarget) without them changing when another
// address is incremented.
//
// An error is returned if either address is not IPv4, or if start is after end.
func ExpandIPRange(start, end net.IP) ([]net.IP, error) {
	first, last := start.To4(), end.To4()
	if first == nil || last == nil {
		return nil, fmt.Errorf("IPv6 address not supported.")
	}
	if bytes.Compare(first, last) > 0 {
		return nil, fmt.Errorf("Invalid IP address range: %s is after %s.", start, end)
	}

	var ips []net.IP
	current := append(net.IP(nil), first...)
	for {
		ips = append(ips, append(net.IP(nil), current...))
		// Stop on the last address itself rather than comparing after the
		// increment: 255.255.255.255 would otherwise wrap around to 0.0.0.0.
		if current.Equal(last) {
			return ips, nil
		}
		IncIP(current)
	}
}

// RangeTargets returns a ScanTarget for every IPv4 address from start to end,
// inclusive. Like targets built from a single address, each one has its Hostname
// set to the address: service discovery dials Hostname, and an empty one would
// make it connect to the local machine instead of the scanned host.
func RangeTargets(start, end net.IP) ([]ScanTarget, error) {
	ips, err := ExpandIPRange(start, end)
	if err != nil {
		return nil, err
	}
	targets := make([]ScanTarget, 0, len(ips))
	for _, ip := range ips {
		targets = append(targets, ScanTarget{Hostname: ip.String(), IPStart: ip})
	}
	return targets, nil
}
