package portdiscovery

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/kubescape/kubescape-network-scanner/pkg/networkscanner"
)

type ScanConfig struct {
	Targets []ScanTarget
	Ports   []int
	Timeout time.Duration
	TcpOnly bool
	UdpOnly bool
}

type ScanTarget struct {
	Hostname string
	IPStart  net.IP
}

// Struct defining the result of the network scanner
func SccanTarget(target ScanTarget, proto string, ports []int, timeout time.Duration, results chan<- networkscanner.ScanResult, wg *sync.WaitGroup) {
	defer wg.Done()
	portsOpen := scanIP(target.IPStart.String(), proto, ports, timeout)
	if len(portsOpen.TCPPorts) > 0 || len(portsOpen.UDPPorts) > 0 {
		result := networkscanner.ScanResult{
			Host:     target.Hostname,
			IP:       target.IPStart,
			TCPPorts: portsOpen.TCPPorts,
			UDPPorts: portsOpen.UDPPorts,
		}
		results <- result
	}
}

func ScanTargets(targets []ScanTarget, tcpOnly bool, udpOnly bool, ports []int, timeout time.Duration) []networkscanner.ScanResult {
	var wg sync.WaitGroup
	results := make(chan networkscanner.ScanResult, len(targets))

	for _, target := range targets {
		wg.Add(1)
		go func(target ScanTarget) {
			defer wg.Done()
			switch {
			case !tcpOnly && !udpOnly:
				tcpPortsOpen := scanIP(target.IPStart.String(), "tcp", ports, timeout)
				udpPortsOpen := scanIP(target.IPStart.String(), "udp", ports, timeout)
				if len(tcpPortsOpen.TCPPorts) > 0 || len(udpPortsOpen.UDPPorts) > 0 {
					result := networkscanner.ScanResult{
						Host:     target.Hostname,
						IP:       target.IPStart,
						TCPPorts: tcpPortsOpen.TCPPorts,
						UDPPorts: udpPortsOpen.UDPPorts,
					}
					results <- result
				}
			case tcpOnly:
				tcpPortsOpen := scanIP(target.IPStart.String(), "tcp", ports, timeout)
				if len(tcpPortsOpen.TCPPorts) > 0 {
					result := networkscanner.ScanResult{
						Host:     target.Hostname,
						IP:       target.IPStart,
						TCPPorts: tcpPortsOpen.TCPPorts,
					}
					results <- result
				}
			case udpOnly:
				udpPortsOpen := scanIP(target.IPStart.String(), "udp", ports, timeout)
				if len(udpPortsOpen.UDPPorts) > 0 {
					result := networkscanner.ScanResult{
						Host:     target.Hostname,
						IP:       target.IPStart,
						UDPPorts: udpPortsOpen.UDPPorts,
					}
					results <- result
				}
			}
		}(target)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var scanResults []networkscanner.ScanResult
	for result := range results {
		scanResults = append(scanResults, result)
	}

	return scanResults
}

// Increment IP address
func IncIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		if ip[j] < 255 {
			ip[j]++
			break
		}
		ip[j] = 0
	}
}

// Define the maximum port number and the number of goroutines to use
const maxPort = 65535
const numGoroutines = 8

/* scanIP scans the specified IP address for open TCP and UDP ports.
 If no ports are specified, it scans all ports. Returns a ScanResult
struct containing the IP address and open TCP and UDP ports. */

func scanIP(ip string, proto string, ports []int, timeout time.Duration) networkscanner.ScanResult {
	// Create a channel to collect open ports and a done channel for synchronization
	openPorts := make(chan int)
	done := make(chan struct{})
	defer close(done)

	// Parse the IP address
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		// Invalid IP address
		fmt.Printf("%s is not a valid IP address\n", ip)
		return networkscanner.ScanResult{}
	}

	// Start a fixed number of goroutines for scanning ports
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, numGoroutines)
	for _, port := range ports {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(port int) {
			defer func() {
				wg.Done()
				<-semaphore
			}()
			if isOpen(ip, port, proto, timeout) {
				//fmt.Printf("%s:%d/%s is open\n", ip, port, proto)
				openPorts <- port
			}
		}(port)
	}

	// If no ports are specified, scan all ports
	if len(ports) == 0 {
		for port := 1; port <= maxPort; port++ {
			wg.Add(1)
			go func(port int) {
				defer wg.Done()
				if isOpen(ip, port, proto, timeout) {
					//fmt.Printf("%s:%d/%s is open\n", ip, port, proto)
					openPorts <- port
				}
			}(port)
		}
	}

	// Start a goroutine to wait for all other goroutines to finish
	go func() {
		wg.Wait()
		close(openPorts)
	}()

	// Collect the open ports from the channel
	openTCPPorts := []int{}
	openUDPPorts := []int{}
	for port := range openPorts {
		switch proto {
		case "tcp":
			openTCPPorts = append(openTCPPorts, port)
		case "udp":
			openUDPPorts = append(openUDPPorts, port)
		}
	}

	// Create and return a ScanResult struct
	result := networkscanner.ScanResult{
		IP:       ipAddr,
		TCPPorts: openTCPPorts,
		UDPPorts: openUDPPorts,
	}
	return result
}

func PrintResults(results []networkscanner.ScanResult) {
	for _, result := range results {
		if len(result.TCPPorts) > 0 || len(result.UDPPorts) > 0 {
			fmt.Printf("%s (%s) has the following ports open:\n", result.Host, result.IP.String())
			if len(result.TCPPorts) > 0 {
				fmt.Printf("TCP: %v\n", result.TCPPorts)
			}
			if len(result.UDPPorts) > 0 {
				fmt.Printf("UDP: %v\n", result.UDPPorts)
			}
		} else {
			fmt.Printf("%s (%s) has an empty list of open ports.\n", result.Host, result.IP.String())
		}
	}
}

// isOpen checks if the specified TCP or UDP port is open on the specified IP address.
// Returns true if the port is open, false otherwise.
func isOpen(ip string, port int, proto string, timeout time.Duration) bool {
	conn, err := net.DialTimeout(proto, fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
