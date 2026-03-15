// Package transport implements Noise protocol encrypted connections between hops.
// Uses Noise_XX pattern: mutual authentication with ephemeral and static keys.
// This encrypts the transport layer — onion encryption is on top of this.
package transport

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/flynn/noise"
)

var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// StaticKey holds a Noise static key pair.
type StaticKey struct {
	Public  []byte
	Private []byte
}

// GenerateStaticKey creates a new Noise static key pair.
func GenerateStaticKey() (*StaticKey, error) {
	kp, err := cipherSuite.GenerateKeypair(nil)
	if err != nil {
		return nil, err
	}
	return &StaticKey{
		Public:  kp.Public,
		Private: kp.Private,
	}, nil
}

// Conn is an encrypted connection using Noise protocol.
type Conn struct {
	raw    net.Conn
	send   *noise.CipherState
	recv   *noise.CipherState
	mu     sync.Mutex
	readMu sync.Mutex
}

// Handshake performs a Noise_XX handshake as initiator (client).
func Handshake(conn net.Conn, localKey *StaticKey) (*Conn, []byte, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Pattern:       noise.HandshakeXX,
		Initiator:     true,
		StaticKeypair: noise.DHKey{Public: localKey.Public, Private: localKey.Private},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("handshake init: %w", err)
	}

	// -> e
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("write msg1: %w", err)
	}
	if err := writeMsg(conn, msg1); err != nil {
		return nil, nil, fmt.Errorf("send msg1: %w", err)
	}

	// <- e, ee, s, es
	msg2, err := readMsg(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("read msg2: %w", err)
	}
	_, _, _, err = hs.ReadMessage(nil, msg2)
	if err != nil {
		return nil, nil, fmt.Errorf("process msg2: %w", err)
	}

	// -> s, se
	msg3, cs0, cs1, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("write msg3: %w", err)
	}
	if err := writeMsg(conn, msg3); err != nil {
		return nil, nil, fmt.Errorf("send msg3: %w", err)
	}

	peerKey := hs.PeerStatic()

	return &Conn{
		raw:  conn,
		send: cs0,
		recv: cs1,
	}, peerKey, nil
}

// AcceptHandshake performs a Noise_XX handshake as responder (relay).
func AcceptHandshake(conn net.Conn, localKey *StaticKey) (*Conn, []byte, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Pattern:       noise.HandshakeXX,
		Initiator:     false,
		StaticKeypair: noise.DHKey{Public: localKey.Public, Private: localKey.Private},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("handshake init: %w", err)
	}

	// <- e
	msg1, err := readMsg(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("read msg1: %w", err)
	}
	_, _, _, err = hs.ReadMessage(nil, msg1)
	if err != nil {
		return nil, nil, fmt.Errorf("process msg1: %w", err)
	}

	// -> e, ee, s, es
	msg2, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("write msg2: %w", err)
	}
	if err := writeMsg(conn, msg2); err != nil {
		return nil, nil, fmt.Errorf("send msg2: %w", err)
	}

	// <- s, se
	msg3, err := readMsg(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("read msg3: %w", err)
	}
	_, cs0, cs1, err := hs.ReadMessage(nil, msg3)
	if err != nil {
		return nil, nil, fmt.Errorf("process msg3: %w", err)
	}

	peerKey := hs.PeerStatic()

	return &Conn{
		raw:  conn,
		send: cs1, // reversed for responder
		recv: cs0,
	}, peerKey, nil
}

// Send encrypts and sends data over the Noise connection.
func (c *Conn) Send(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	encrypted, err := c.send.Encrypt(nil, nil, data)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	return writeMsg(c.raw, encrypted)
}

// Recv receives and decrypts data from the Noise connection.
func (c *Conn) Recv() ([]byte, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	encrypted, err := readMsg(c.raw)
	if err != nil {
		return nil, err
	}
	plaintext, err := c.recv.Decrypt(nil, nil, encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// Close closes the underlying connection.
func (c *Conn) Close() error {
	return c.raw.Close()
}

// RemoteAddr returns the remote address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.raw.RemoteAddr()
}

// writeMsg writes a length-prefixed message.
func writeMsg(w io.Writer, data []byte) error {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(data)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// readMsg reads a length-prefixed message.
func readMsg(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header)
	if length > 1<<20 { // 1MB max
		return nil, fmt.Errorf("message too large: %d", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data, nil
}
