package mirror

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// Message types for TCP communication
const (
	MsgTypeEAPRequest  byte = 0x01 // B->A: forward EAP request from real server
	MsgTypeEAPResponse byte = 0x02 // A->B: forward EAP response from supplicant
	MsgTypeEAPSuccess  byte = 0x03 // A->B: EAP success
	MsgTypeEAPFailure  byte = 0x04 // A->B: EAP failure
)

// Message represents a TCP message between client and server
// Format: [Length:2bytes][Type:1byte][Payload:variable]
type Message struct {
	Type    byte
	Payload []byte
}

// WriteMessage writes a message to the connection
func WriteMessage(conn net.Conn, msg *Message) error {
	length := uint16(1 + len(msg.Payload)) // type + payload
	buf := make([]byte, 2+length)
	binary.BigEndian.PutUint16(buf[0:2], length)
	buf[2] = msg.Type
	copy(buf[3:], msg.Payload)

	_, err := conn.Write(buf)
	return err
}

// ReadMessage reads a message from the connection
func ReadMessage(conn net.Conn) (*Message, error) {
	// Read length
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lenBuf)
	if length < 1 {
		return nil, fmt.Errorf("invalid message length: %d", length)
	}

	// Read type and payload
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}

	return &Message{
		Type:    data[0],
		Payload: data[1:],
	}, nil
}
