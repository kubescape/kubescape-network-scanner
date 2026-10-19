package portdiscovery

import (
	"net"
	"testing"
)

func ipStrings(ips []net.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestExpandIPRange(t *testing.T) {
	tests := []struct {
		name       string
		start, end string
		want       []string
	}{
		{"small range", "10.0.0.1", "10.0.0.3", []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{"single address", "10.0.0.5", "10.0.0.5", []string{"10.0.0.5"}},
		// These used to compare as strings: "10.0.0.9" > "10.0.0.10".
		{"last octet crosses a digit boundary", "10.0.0.9", "10.0.0.11", []string{"10.0.0.9", "10.0.0.10", "10.0.0.11"}},
		{"carries into the next octet", "10.0.0.254", "10.0.1.2", []string{"10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1", "10.0.1.2"}},
		{"carries across several octets", "10.0.255.255", "10.1.0.1", []string{"10.0.255.255", "10.1.0.0", "10.1.0.1"}},
		{"last address of the IPv4 space does not wrap", "255.255.255.254", "255.255.255.255", []string{"255.255.255.254", "255.255.255.255"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ExpandIPRange(net.ParseIP(tc.start), net.ParseIP(tc.end))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !equalStrings(ipStrings(got), tc.want) {
				t.Errorf("ExpandIPRange(%s, %s) = %v, want %v", tc.start, tc.end, ipStrings(got), tc.want)
			}
		})
	}
}

func TestExpandIPRange_FullLastOctet(t *testing.T) {
	got, err := ExpandIPRange(net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.20"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 20 {
		t.Fatalf("got %d addresses, want 20: %v", len(got), ipStrings(got))
	}
	if got[0].String() != "192.168.1.1" || got[19].String() != "192.168.1.20" {
		t.Errorf("range runs %s..%s, want 192.168.1.1..192.168.1.20", got[0], got[19])
	}
	for i := 1; i < len(got); i++ {
		if got[i].Equal(got[i-1]) {
			t.Errorf("address %s appears twice in a row at index %d", got[i], i)
		}
	}
}

// The returned addresses must not share storage: ScanTarget keeps the net.IP it
// is given, so aliasing made every target in a range end up as the same address.
func TestExpandIPRange_AddressesAreIndependent(t *testing.T) {
	got, err := ExpandIPRange(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.3"))
	if err != nil {
		t.Fatal(err)
	}
	before := ipStrings(got)
	IncIP(got[0])
	after := ipStrings(got)
	if after[1] != before[1] || after[2] != before[2] {
		t.Errorf("incrementing the first address changed others: before %v, after %v", before, after)
	}
}

func TestExpandIPRange_ReturnsIPv4(t *testing.T) {
	// net.ParseIP returns the 16-byte form; the results should be plain IPv4.
	got, err := ExpandIPRange(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range got {
		if ip.To4() == nil {
			t.Errorf("%v is not an IPv4 address", ip)
		}
	}
}

func TestExpandIPRange_Errors(t *testing.T) {
	tests := []struct {
		name       string
		start, end string
	}{
		{"start after end", "10.0.0.5", "10.0.0.1"},
		{"start after end, numerically but not as strings", "10.0.0.10", "10.0.0.9"},
		{"IPv6 start", "::1", "10.0.0.1"},
		{"IPv6 end", "10.0.0.1", "::2"},
		{"both IPv6", "fe80::1", "fe80::5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ExpandIPRange(net.ParseIP(tc.start), net.ParseIP(tc.end))
			if err == nil {
				t.Fatalf("got %v, want an error", ipStrings(got))
			}
			if got != nil {
				t.Errorf("got %v alongside an error, want nil", ipStrings(got))
			}
		})
	}
}

func TestRangeTargets_SetHostnameToTheAddress(t *testing.T) {
	targets, err := RangeTargets(net.ParseIP("10.0.0.9"), net.ParseIP("10.0.0.11"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.9", "10.0.0.10", "10.0.0.11"}
	if len(targets) != len(want) {
		t.Fatalf("got %d targets, want %d", len(targets), len(want))
	}
	for i, target := range targets {
		if target.Hostname != want[i] {
			t.Errorf("target %d Hostname = %q, want %q (an empty hostname makes service discovery dial the local machine)", i, target.Hostname, want[i])
		}
		if target.IPStart.String() != want[i] {
			t.Errorf("target %d IPStart = %s, want %s", i, target.IPStart, want[i])
		}
	}
}

func TestRangeTargets_PropagatesRangeErrors(t *testing.T) {
	if targets, err := RangeTargets(net.ParseIP("10.0.0.5"), net.ParseIP("10.0.0.1")); err == nil || targets != nil {
		t.Errorf("got (%v, %v), want (nil, error) for a reversed range", targets, err)
	}
	if targets, err := RangeTargets(net.ParseIP("::1"), net.ParseIP("::3")); err == nil || targets != nil {
		t.Errorf("got (%v, %v), want (nil, error) for an IPv6 range", targets, err)
	}
}
