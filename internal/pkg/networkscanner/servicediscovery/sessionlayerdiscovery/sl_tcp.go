package networkscanner

import (
	"fmt"
	"net"
)

type TcpSessionHandler struct {
	host string
	port int
	conn net.Conn
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
