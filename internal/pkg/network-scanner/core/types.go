package networkscanner

type TransportProtocol string
type PresentationLayerProtocol string
type SessionLayerProtocol string

const (
	TCP              TransportProtocol         = "tcp"
	UDP              TransportProtocol         = "udp"
	TLS              SessionLayerProtocol      = "tls"
	SSH              SessionLayerProtocol      = "ssh"
	NO_SESSION_LAYER SessionLayerProtocol      = "no_session_layer"
	HTTP             PresentationLayerProtocol = "http"
)

///////////////////////////////////////////////////////////////////////////////
// Session Layer Protocols
///////////////////////////////////////////////////////////////////////////////

type iSessionHandler interface {
	Connect() error
	Destory() error
	Write([]byte) (int, error)
	Read([]byte) (int, error)
	GetHost() string
	GetPort() int
}

type iSessionLayerDiscoveryResult interface {
	Protocol() SessionLayerProtocol
	GetIsDetected() bool
	GetProperties() map[string]interface{}
	GetSessionHandler() (iSessionHandler, error)
}

type SessionLayerProtocolDiscovery interface {
	Protocol() TransportProtocol
	SessionLayerDiscover(hostAddr string, port int) (iSessionLayerDiscoveryResult, error)
}

///////////////////////////////////////////////////////////////////////////////
// Presentation Layer Protocols
///////////////////////////////////////////////////////////////////////////////

type iPresentationDiscoveryResult interface {
	Protocol() PresentationLayerProtocol
	GetIsDetected() bool
	GetProperties() map[string]interface{}
}

type PresentationLayerDiscovery interface {
	Protocol() PresentationLayerProtocol
	Discover(sessionHandler iSessionHandler) (iPresentationDiscoveryResult, error)
}

///////////////////////////////////////////////////////////////////////////////
// Application Layer Protocols
///////////////////////////////////////////////////////////////////////////////

type iApplicationDiscoveryResult interface {
	Protocol() string
	GetIsDetected() bool
	GetProperties() map[string]interface{}
	GetIsAuthRequired() bool
}

type ApplicationLayerDiscovery interface {
	Protocol() string
	Discover(sessionHandler iSessionHandler, presenationLayerDiscoveryResult iPresentationDiscoveryResult) (iApplicationDiscoveryResult, error)
}
