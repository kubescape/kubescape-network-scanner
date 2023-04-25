# kubescape-network-scanner
Network scan and service discovery package

## Basic network package

See the network scanner and service discovery package and service discovery [here](internal/pkg/network-scanner/).

The main interface is defined in [interface.go](internal/pkg/network-scanner/interface.go)

There are several constants defined for target types, port types, and authentication status. These constants are used to specify the type of target (IP, IP list, IP range, hostname), the type of port (single, list, range), and the authentication status (authenticated, unauthenticated, partially authenticated) respectively.

The TargetDescription struct defines the targets of the network scanner. It has fields to specify the target type, list of IP addresses, IP range start and end, hostname, port type, and ports or port range start and end. It also has fields to specify whether to scan TCP ports, UDP ports, or both.

The ScanResult struct defines the results of the network scan. It has fields to specify the IP address, port number, service name, authentication status, and whether the connection is secure (TLS/SSL).

The NetworkScanner interface defines a method Scan that takes a TargetDescription argument and returns an array of ScanResult and an error. The Scan method should perform a network scan and return an array of ScanResult for all open ports and their associated services.


