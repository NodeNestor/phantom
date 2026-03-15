// Package protocol defines the wire protocol for phantom.
// All messages are framed as: [2-byte big-endian length][payload]
// Payload is always encrypted at the transport layer (Noise).
package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Message types
const (
	// Circuit setup
	MsgCircuitCreate  byte = 0x01 // Client -> Relay: extend circuit
	MsgCircuitCreated byte = 0x02 // Relay -> Client: circuit established
	MsgCircuitDestroy byte = 0x03 // Either direction: tear down circuit

	// Data relay
	MsgRelayData byte = 0x10 // Wrapped data payload
	MsgRelayEnd  byte = 0x11 // Stream closed

	// Token auth
	MsgTokenPresent byte = 0x20 // Present a blind token
	MsgTokenAccept  byte = 0x21 // Token accepted
	MsgTokenReject  byte = 0x22 // Token rejected

	// Connect to destination (exit node)
	MsgConnect    byte = 0x30 // Request connection to target
	MsgConnected  byte = 0x31 // Connection established
	MsgConnectErr byte = 0x32 // Connection failed
)

const (
	MaxPayloadSize = 65535 - 3 // max payload in one frame
	HeaderSize     = 3         // 2 bytes length + 1 byte type
)

// Frame represents a protocol message.
type Frame struct {
	Type    byte
	Payload []byte
}

// WriteFrame writes a framed message to w.
func WriteFrame(w io.Writer, f Frame) error {
	if len(f.Payload) > MaxPayloadSize {
		return fmt.Errorf("payload too large: %d > %d", len(f.Payload), MaxPayloadSize)
	}
	header := make([]byte, HeaderSize)
	totalLen := uint16(len(f.Payload) + 1) // +1 for type byte
	binary.BigEndian.PutUint16(header[0:2], totalLen)
	header[2] = f.Type
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(f.Payload) > 0 {
		if _, err := w.Write(f.Payload); err != nil {
			return err
		}
	}
	return nil
}

// ReadFrame reads a framed message from r.
func ReadFrame(r io.Reader) (Frame, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return Frame{}, err
	}
	totalLen := binary.BigEndian.Uint16(header[0:2])
	if totalLen == 0 {
		return Frame{}, fmt.Errorf("invalid frame: zero length")
	}
	msgType := header[2]
	payloadLen := int(totalLen) - 1
	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return Frame{}, err
		}
	}
	return Frame{Type: msgType, Payload: payload}, nil
}
