package cmd

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/kubescape/kubescape-network-scanner/internal/pkg/networkscanner/portdiscovery"
	"github.com/kubescape/kubescape-network-scanner/internal/pkg/networkscanner/servicediscovery"
	"github.com/spf13/cobra"
)

var config portdiscovery.ScanConfig

var (
	// Input flags
	ipFlag       string
	ipListFlag   []string
	ipRangeFlag  string
	hostnameFlag []string
	portFlag     []int
	tcpFlag      bool
	udpFlag      bool
	serviceFlag  []string

	// Scan command
	ScanCmd = &cobra.Command{
		Use:   "Scan",
		Short: "Discover open ports and services on a given target or a list of targets.",
		Long:  "Discover open ports with services on a given target using TCP and/or UDP protocols.",
		RunE:  scan,
	}
)

func init() {
	// Define input flags
	ScanCmd.Flags().StringVar(&ipFlag, "ip", "", "IP address to scan")
	ScanCmd.Flags().StringSliceVar(&ipListFlag, "iplist", []string{}, "List of IP addresses to scan")
	ScanCmd.Flags().StringVar(&ipRangeFlag, "iprange", "", "IP range to scan (e.g. 192.168.1.1-192.168.1.10)")
	ScanCmd.Flags().StringSliceVar(&hostnameFlag, "hostname", []string{}, "Hostname to scan")
	ScanCmd.Flags().IntSliceVar(&portFlag, "port", []int{}, "Port number(s) to scan")
	ScanCmd.Flags().BoolVar(&tcpFlag, "tcp", false, "Scan only TCP ports")
	ScanCmd.Flags().BoolVar(&udpFlag, "udp", false, "Scan only UDP ports")
	ScanCmd.Flags().StringSliceVar(&serviceFlag, "service", []string{}, "Service type(s) to scan (e.g. http, ssh)")

	// Add Scan command to root command
	rootCmd.AddCommand(ScanCmd)
}

func scan(cmd *cobra.Command, args []string) error {
	config, err := parseArgs(args)
	if err != nil {
		return err
	}

	// Scan targets
	scanResults := portdiscovery.ScanTargets(config.Targets, config.TcpOnly, config.UdpOnly, config.Ports, config.Timeout)

	// Service discovery for each port discovered
	var serviceScanResults []servicediscovery.ScanResult
	for _, scanResult := range scanResults {
		port := scanResult.Port
		serviceScanResult := servicediscovery.ScanTargets(config.Targets, []int{port})
		serviceScanResults = append(serviceScanResults, serviceScanResult...)
	}

	// Print scan results
	portdiscovery.PrintResults(scanResults)
	servicediscovery.PrintResults(serviceScanResults)

	return nil
}

func parseArgs(args []string) (*portdiscovery.ScanConfig, error) {
	config := &portdiscovery.ScanConfig{}

	if len(args) < 1 {
		return nil, fmt.Errorf("Usage: Scan [--tcp|--udp] <host or ip_address or ip_range> [ports...]")
	}

	targetStr := args[0]
	if strings.Contains(targetStr, "-") { // check if target is a range of IP addresses
		ipRange := strings.Split(targetStr, "-")
		startIP := net.ParseIP(ipRange[0])
		endIP := net.ParseIP(ipRange[1])
		if startIP == nil || endIP == nil {
			return nil, fmt.Errorf("Invalid IP address range.")
		}
		for ip := startIP; ip.String() <= endIP.String(); portdiscovery.IncIP(ip) {
			if ip.To4() == nil {
				fmt.Printf("IPv6 address not supported: %s\n", ip.String())
				continue
			}
			target := portdiscovery.ScanTarget{IPStart: ip}
			config.Targets = append(config.Targets, target)
		}
	} else {
		target := portdiscovery.ScanTarget{Hostname: targetStr}
		if ip := net.ParseIP(target.Hostname); ip != nil {
			if ip.To4() == nil {
				return nil, fmt.Errorf("IPv6 address not supported.")
			}
			target.IPStart = ip
		} else {
			// Resolve hostname
			addrs, err := net.LookupHost(target.Hostname)
			if err != nil {
				return nil, fmt.Errorf("Failed to resolve hostname: %s", target.Hostname)
			}
			target.IPStart = net.ParseIP(addrs[0])
			if target.IPStart.To4() == nil {
				return nil, fmt.Errorf("IPv6 address not supported.")
			}
		}
		config.Targets = append(config.Targets, target)
	}

	if len(args) > 1 {
		for _, portStr := range args[1:] {
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, fmt.Errorf("Invalid port number: %s", portStr)
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("Port number out of range: %s", portStr)
			}
			config.Ports = append(config.Ports, port)
		}
	}

	// Parse TCP and UDP flags
	if tcpFlag && !udpFlag {
		config.TcpOnly = true
	}
	if udpFlag && !tcpFlag {
		config.UdpOnly = true
	}

	return config, nil
}
