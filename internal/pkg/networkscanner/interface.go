package networkscanner

import "net"

////////////////////////////////////////////////////////////////////////////////////////
// Interface definition for network scanner and service discovery
////////////////////////////////////////////////////////////////////////////////////////

const (
	TARGET_TYPE_IP                                = "IP"
	TARGET_TYPE_IP_LIST                           = "IP_LIST"
	TARGET_TYPE_IP_RANGE                          = "IP_RANGE"
	TARGET_TYPE_HOSTNAME                          = "HOSTNAME"
	PORT_TYPE_SINGLE                              = "SINGLE"
	PORT_TYPE_LIST                                = "LIST"
	PORT_TYPE_RANGE                               = "RANGE"
	AUTHENTICATION_STATUS_AUTHENTICATED           = "AUTHENTICATED"
	AUTHENTICATION_STATUS_UNAUTHENTICATED         = "UNAUTHENTICATED"
	AUTHENTICATION_STATUS_PARTIALLY_AUTHENTICATED = "PARTIALLY_AUTHENTICATED"
)

// Struct defining targets of the network scanner
type TargetDescription struct {
	TargetType string
	IPs        []net.IP
	IPStart    net.IP
	IPEnd      net.IP
	Hostname   string
	PortType   string
	Ports      []int
	PortStart  int
	PortEnd    int
	TcpPorts   bool
	UdpPorts   bool
}

// Struct defining the result of the network scanner
type ScanResult struct {
	host           string
	IP             net.IP
	TCPPorts       []int
	UDPPorts       []int
	Service        string // Maybe we need to break this down into more fields (HTTP, Kubelete etc.)
	Authenticated  string
	SecureProtocol bool // TLS/SSL
}

// Interface for network scanner
type NetworkScanner interface {
	Scan(target TargetDescription) ([]ScanResult, error)
}
