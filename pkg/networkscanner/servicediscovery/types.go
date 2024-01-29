package servicediscovery

type TransportProtocol string
type PresentationLayerProtocol string
type SessionLayerProtocol string

const (
	TCP              TransportProtocol         = "tcp"
	UDP              TransportProtocol         = "udp"
	TLS              SessionLayerProtocol      = "tls"
	SSH              SessionLayerProtocol      = "ssh"
	NO_SESSION_LAYER SessionLayerProtocol      = "tcp"
	HTTP             PresentationLayerProtocol = "http"
)

///////////////////////////////////////////////////////////////////////////////
// Session Layer Protocols
///////////////////////////////////////////////////////////////////////////////

type ISessionHandler interface {
	Connect() error
	Destory() error
	Write([]byte) (int, error)
	Read([]byte) (int, error)
	GetHost() string
	GetPort() int
}

type ISessionLayerDiscoveryResult interface {
	Protocol() SessionLayerProtocol
	GetIsDetected() bool
	GetProperties() map[string]interface{}
	GetSessionHandler() (ISessionHandler, error)
}

type SessionLayerProtocolDiscovery interface {
	Protocol() TransportProtocol
	SessionLayerDiscover(hostAddr string, port int) (ISessionLayerDiscoveryResult, error)
}

///////////////////////////////////////////////////////////////////////////////
// Presentation Layer Protocols
///////////////////////////////////////////////////////////////////////////////

type IPresentationDiscoveryResult interface {
	Protocol() PresentationLayerProtocol
	GetIsDetected() bool
	GetProperties() map[string]interface{}
}

type PresentationLayerDiscovery interface {
	Protocol() PresentationLayerProtocol
	Discover(sessionHandler ISessionHandler) (IPresentationDiscoveryResult, error)
}

///////////////////////////////////////////////////////////////////////////////
// Application Layer Protocols
///////////////////////////////////////////////////////////////////////////////

type IApplicationDiscoveryResult interface {
	Protocol() string
	GetIsDetected() bool
	GetProperties() map[string]interface{}
	GetIsAuthRequired() bool
}

type ApplicationLayerDiscovery interface {
	Protocol() string
	Discover(sessionHandler ISessionHandler, presenationLayerDiscoveryResult IPresentationDiscoveryResult) (IApplicationDiscoveryResult, error)
}
