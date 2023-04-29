package networkscanner

import (
	"bytes"
	"encoding/binary"
)

type MysqlDiscoveryResult struct {
	IsDetected bool
	properties map[string]interface{}
}

type MysqlDiscovery struct{}

func (r *MysqlDiscoveryResult) Protocol() string {
	return "my-sql"
}

func (r *MysqlDiscoveryResult) GetIsAuthRequired() bool {
	return false
}

func (r *MysqlDiscoveryResult) GetIsDetected() bool {
	return r.IsDetected
}

func (r *MysqlDiscoveryResult) GetProperties() map[string]interface{} {
	return r.properties
}

func (d *MysqlDiscovery) Protocol() string {
	return "my-sql"
}

func (d *MysqlDiscovery) Discover(sessionHandler iSessionHandler, presentationLayerDiscoveryResult iPresentationDiscoveryResult) (iApplicationDiscoveryResult, error) {
	err := sessionHandler.Connect()
	if err != nil {
		return nil, err
	}

	// Decode initial handshake packet
	packet := &InitialHandshakePacket{}
	err = packet.Decode(sessionHandler)
	if err != nil {
		return nil, err
	}

	// Create MySQL discovery result
	return &MysqlDiscoveryResult{
		IsDetected: true,
		properties: map[string]interface{}{
			"ServerVersion":   packet.ServerVersion,
			"protocolVersion": packet.ProtocolVersion,
			"ConnectionId":    packet.ConnectionId,
		},
	}, nil
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

func (r *InitialHandshakePacket) Decode(sessionHandler iSessionHandler) error {
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
