package sessionlayerdiscovery

import (
	"fmt"
	"net"

	"github.com/kubescape/kubescape-network-scanner/internal/pkg/networkscanner/servicediscovery"
)

type TcpSessionDiscovery struct {
}

type TcpSessionDiscoveryResult struct {
	host string
	port int
}
type TcpSessionHandler struct {
	host string
	port int
	conn net.Conn
}

func (d *TcpSessionDiscovery) Protocol() servicediscovery.TransportProtocol {
	return servicediscovery.TCP
}

func (d *TcpSessionDiscovery) SessionLayerDiscover(hostAddr string, port int) (servicediscovery.ISessionLayerDiscoveryResult, error) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", hostAddr, port))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return &TcpSessionDiscoveryResult{host: hostAddr, port: port}, nil
}

func (d *TcpSessionDiscoveryResult) Protocol() servicediscovery.SessionLayerProtocol {
	return servicediscovery.NO_SESSION_LAYER
}

func (d *TcpSessionDiscoveryResult) GetIsDetected() bool {
	return true
}

func (d *TcpSessionDiscoveryResult) GetProperties() map[string]interface{} {
	return nil
}

func (d *TcpSessionDiscoveryResult) GetSessionHandler() (servicediscovery.ISessionHandler, error) {
	return &TcpSessionHandler{host: d.host, port: d.port}, nil
}

func (d *TcpSessionHandler) Connect() error {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", d.host, d.port))
	if err != nil {
		return err
	}
	d.conn = conn
	return nil
}

func (d *TcpSessionHandler) Destory() error {
	return d.conn.Close()
}

func (d *TcpSessionHandler) Write(data []byte) (int, error) {
	return d.conn.Write(data)
}

func (d *TcpSessionHandler) Read(data []byte) (int, error) {
	return d.conn.Read(data)
}

func (d *TcpSessionHandler) GetHost() string {
	return d.host
}

func (d *TcpSessionHandler) GetPort() int {
	return d.port
}
