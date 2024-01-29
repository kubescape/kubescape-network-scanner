package applicationlayerdiscovery

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"fmt"
	"strings"

	_ "github.com/go-sql-driver/mysql"

	"github.com/kubescape/kubescape-network-scanner/pkg/networkscanner/servicediscovery"
)

type MysqlDiscoveryResult struct {
	IsDetected      bool
	isAuthenticated bool
	properties      map[string]interface{}
}

type MysqlDiscovery struct{}

func (r *MysqlDiscoveryResult) Protocol() string {
	return "mysql"
}

func (r *MysqlDiscoveryResult) GetIsAuthRequired() bool {
	return r.isAuthenticated
}

func (r *MysqlDiscoveryResult) GetIsDetected() bool {
	return r.IsDetected
}

func (r *MysqlDiscoveryResult) GetProperties() map[string]interface{} {
	return r.properties
}

func (d *MysqlDiscovery) Protocol() string {
	return "mysql"
}

func (d *MysqlDiscovery) Discover(sessionHandler servicediscovery.ISessionHandler, presentationLayerDiscoveryResult servicediscovery.IPresentationDiscoveryResult) (servicediscovery.IApplicationDiscoveryResult, error) {
	dataSourceName := fmt.Sprintf("root:@tcp(%s:%d)/", sessionHandler.GetHost(), sessionHandler.GetPort())

	// Attempt to open a connection
	db, err := sql.Open("mysql", dataSourceName)
	if err != nil {
		return &MysqlDiscoveryResult{
			IsDetected:      false,
			isAuthenticated: true,
			properties:      nil, // Set properties to nil as it's not used in this case
		}, err
	}
	defer db.Close()
	db.SetMaxIdleConns(0)

	// Ping the server
	err = db.Ping()
	isMySql := false
	isAuthRequired := true
	if err != nil {
		if strings.Contains(err.Error(), "Access denied") {
			// If access is denied, that means the server is there but requires authentication
			isMySql = true
			isAuthRequired = true
		} else {
			// Some other error means the server is not there
			isMySql = false
		}
	} else {
		// No error means the server is there and does not require authentication
		isMySql = true
		isAuthRequired = false
	}

	result := &MysqlDiscoveryResult{
		IsDetected:      isMySql,
		isAuthenticated: isAuthRequired,
		properties:      nil, // Set properties to nil as it's not used in this case
	}

	return result, nil

}

// PacketHeader represents packet header
type PacketHeader struct {
	Length     uint32
	SequenceId uint8
}

// InitialHandshakePacket represents initial handshake packet sent by MySQL Server
type InitialHandshakePacket struct {
	ProtocolVersion uint8
	ServerVersion   []byte
	ConnectionId    uint32
	header          *PacketHeader
}

func (r *InitialHandshakePacket) Decode(sessionHandler servicediscovery.ISessionHandler) error {
	data := make([]byte, 1024)
	_, err := sessionHandler.Read(data)
	if err != nil {
		return err
	}

	header := &PacketHeader{}
	ln := []byte{data[0], data[1], data[2], 0x00}
	header.Length = binary.LittleEndian.Uint32(ln)
	// a single byte integer is the same in BigEndian and LittleEndian
	header.SequenceId = data[3]

	r.header = header

	// Assign payload only data to new var just for convenience
	payload := data[4 : header.Length+4]
	position := 0

	// Check protocol version
	r.ProtocolVersion = payload[0]

	position += 1

	// Extract server version
	index := bytes.IndexByte(payload, byte(0x00))
	r.ServerVersion = payload[position:index]
	position = index + 1

	// Extract connection ID
	connectionId := payload[position : position+4]
	id := binary.LittleEndian.Uint32(connectionId)
	r.ConnectionId = id
	position += 4
	// Return nil error since there is no error
	return nil
}
