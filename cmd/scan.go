package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/kubescape/kubescape-network-scanner/pkg/networkscanner/portdiscovery"
	"github.com/spf13/cobra"
)

var config portdiscovery.ScanConfig
var jsonFileName string

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
	jsonflag     bool
	// Output file flag
	outputFileFlag string

	// Scan command
	ScanCmd = &cobra.Command{
		Use:   "scan",
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
	ScanCmd.Flags().BoolVar(&jsonflag, "json", false, "Output results in JSON format")
	// Output file flag
	ScanCmd.Flags().StringVar(&outputFileFlag, "output", "", "Output file to write results to")

	// Add Scan command to root command
	rootCmd.AddCommand(ScanCmd)
}

func scan(cmd *cobra.Command, args []string) error {
	discoveryResults := []map[string]interface{}{}
	config, err := parseArgs(args)
	if err != nil {
		return err
	}

	if outputFileFlag != "" {
		fmt.Printf("Output file: %s\n", outputFileFlag)
	}

	// Scan targets
	scanResults := portdiscovery.ScanTargets(config.Targets, config.TcpOnly, config.UdpOnly, config.Ports, config.Timeout)

	// Print scan results
	if !jsonflag {
		portdiscovery.PrintResults(scanResults)
	}

	// Iterate through each scan result and perform service discovery
	for _, target := range scanResults {
		// Perform service discovery for open TCP ports
		for _, port := range target.TCPPorts {
			discoveryResult, err := ScanTargets(context.Background(), target.Host, port)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error while discovering services on %s:%d: %s\n", target.Host, port, err)
				continue
			}

			// Print discovered services
			fmt.Fprintf(os.Stderr, "Services discovered on %s:%d:\n", target.Host, port)
			fmt.Fprintf(os.Stderr, "Session Layer: %s\n", discoveryResult.SessionLayer)
			fmt.Fprintf(os.Stderr, "Presentation Layer: %s\n", discoveryResult.PresentationLayer)
			fmt.Fprintf(os.Stderr, "Application Layer: %s\n", discoveryResult.ApplicationLayer)
			fmt.Fprintf(os.Stderr, "Authenticated: %v\n", discoveryResult.IsAuthenticated)
			fmt.Fprintf(os.Stderr, "Properties: %s\n", discoveryResult.Properties)

			// Store discovery results in a map
			resultMap := map[string]interface{}{
				"host":              target.Host,
				"port":              port,
				"type":              "tcp",
				"sessionlayer":      discoveryResult.SessionLayer,
				"presentationlayer": discoveryResult.PresentationLayer,
				"applicationlayer":  discoveryResult.ApplicationLayer,
				"service":           discoveryResult.ApplicationLayer,
				"authenticated":     discoveryResult.IsAuthenticated,
				"properties":        discoveryResult.Properties,
			}

			// Append results to discoveryResults slice
			discoveryResults = append(discoveryResults, resultMap)
		}
		// Perform service discovery for open UDP ports
		for _, port := range target.UDPPorts {
			discoveryResult, err := ScanTargets(context.Background(), target.Host, port)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error while discovering services on %s:%d: %s\n", target.Host, port, err)
				continue
			}

			// Print discovered services
			fmt.Fprintf(os.Stderr, "Services discovered on %s:%d:\n", target.Host, port)
			fmt.Fprintf(os.Stderr, "Session Layer: %s\n", discoveryResult.SessionLayer)
			fmt.Fprintf(os.Stderr, "Presentation Layer: %s\n", discoveryResult.PresentationLayer)
			fmt.Fprintf(os.Stderr, "Application Layer: %s\n", discoveryResult.ApplicationLayer)
			fmt.Fprintf(os.Stderr, "Authenticated: %v\n", discoveryResult.IsAuthenticated)
			fmt.Fprintf(os.Stderr, "Properties: %s\n", discoveryResult.Properties)
			// Store discovery results in a map
			resultMap := map[string]interface{}{
				"host":              target.Host,
				"port":              port,
				"type":              "udp",
				"sessionlayer":      discoveryResult.SessionLayer,
				"presentationlayer": discoveryResult.PresentationLayer,
				"applicationlayer":  discoveryResult.ApplicationLayer,
				"service":           discoveryResult.ApplicationLayer,
				"authenticated":     discoveryResult.IsAuthenticated,
				"properties":        discoveryResult.Properties,
			}

			// Append results to discoveryResults slice
			discoveryResults = append(discoveryResults, resultMap)
		}
	}

	// Write results
	if jsonflag {
		var outputFile *os.File = os.Stdout
		// Check if output file is specified
		if outputFileFlag != "" {
			// Open output file
			var err error
			outputFile, err = os.OpenFile(outputFileFlag, os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return err
			}
			defer outputFile.Close()
		}
		// Encode discoveryResults slice as JSON and write to file
		jsonEncoder := json.NewEncoder(outputFile)
		err = jsonEncoder.Encode(discoveryResults)
		if err != nil {
			return err
		}

		fmt.Printf("JSON data stored in file: %s\n", jsonFileName)
	}

	return nil
}

// Function to check if the string is an IP address range
func isIPRange(ip string) bool {
	if strings.Contains(ip, "-") {
		// Split IP address range
		ipRange := strings.Split(ip, "-")
		startIP := net.ParseIP(ipRange[0])
		endIP := net.ParseIP(ipRange[1])
		if startIP == nil || endIP == nil {
			return false
		}
		return true
	}
	return false
}

func parseArgs(args []string) (*portdiscovery.ScanConfig, error) {
	config := &portdiscovery.ScanConfig{}

	if len(args) < 1 {
		return nil, fmt.Errorf("Usage: scan [--tcp|--udp] <host or ip_address or ip_range> [ports...]")
	}

	targetStr := args[0]
	if isIPRange(targetStr) { // check if target is a range of IP addresses
		ipRange := strings.Split(targetStr, "-")
		startIP := net.ParseIP(ipRange[0])
		endIP := net.ParseIP(ipRange[1])
		if startIP == nil || endIP == nil {
			return nil, fmt.Errorf("Invalid IP address range.")
		}
		for ip := startIP; ip.String() <= endIP.String(); portdiscovery.IncIP(ip) {
			if ip.To4() == nil {
				fmt.Fprintf(os.Stderr, "IPv6 address not supported: %s\n", ip.String())
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
