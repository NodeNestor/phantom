// Package circuit manages multi-hop circuits.
// The client builds circuits by selecting random relay paths,
// wrapping data in onion layers with embedded tokens for each hop.
package circuit

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ludde/phantom/internal/directory"
	"github.com/ludde/phantom/internal/onion"
	"github.com/ludde/phantom/internal/token"
	"github.com/ludde/phantom/internal/transport"
)

// Circuit represents an established multi-hop path.
type Circuit struct {
	ID        uint32
	Path      []*directory.Relay
	EntryConn *transport.Conn
	CreatedAt time.Time
	closed    atomic.Bool
}

// Manager handles circuit creation, reuse, and teardown.
type Manager struct {
	dir      *directory.Directory
	circuits map[uint32]*Circuit
	mu       sync.RWMutex
	nextID   atomic.Uint32
	hops     int
	tokens   []token.Token
	tokenMu  sync.Mutex
	entryKey *transport.StaticKey
}

func NewManager(dir *directory.Directory, hops int, entryKey *transport.StaticKey) *Manager {
	return &Manager{
		dir:      dir,
		circuits: make(map[uint32]*Circuit),
		hops:     hops,
		entryKey: entryKey,
	}
}

func (m *Manager) SetTokens(tokens []token.Token) {
	m.tokenMu.Lock()
	defer m.tokenMu.Unlock()
	m.tokens = tokens
}

func (m *Manager) takeTokens(n int) ([]token.Token, error) {
	m.tokenMu.Lock()
	defer m.tokenMu.Unlock()
	if len(m.tokens) < n {
		return nil, fmt.Errorf("need %d tokens, have %d", n, len(m.tokens))
	}
	taken := make([]token.Token, n)
	copy(taken, m.tokens[:n])
	m.tokens = m.tokens[n:]
	return taken, nil
}

func (m *Manager) TokenCount() int {
	m.tokenMu.Lock()
	defer m.tokenMu.Unlock()
	return len(m.tokens)
}

// BuildCircuit creates a new circuit, connects to entry, and sends the
// onion-wrapped data containing embedded tokens for each hop.
func (m *Manager) BuildCircuit(destAddr string) (*Circuit, error) {
	path, err := m.dir.SelectPath(m.hops)
	if err != nil {
		return nil, fmt.Errorf("select path: %w", err)
	}

	// Need one token per hop
	tokens, err := m.takeTokens(len(path))
	if err != nil {
		return nil, err
	}

	// Connect to entry relay with 0x00 prefix
	rawConn, err := net.DialTimeout("tcp", path[0].Address, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to entry %s: %w", path[0].Address, err)
	}
	// Enable TCP keepalive for long-lived streams
	if tc, ok := rawConn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
		tc.SetNoDelay(true)
	}

	// Send client connection type prefix
	if _, err := rawConn.Write([]byte{0x00}); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("write conn type: %w", err)
	}

	// Noise handshake
	noiseConn, peerKey, err := transport.Handshake(rawConn, m.entryKey)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}

	// Verify the entry relay's Noise static key if one is stored in the directory
	if path[0].NoisePublicKey != nil {
		if len(peerKey) != len(path[0].NoisePublicKey) || !bytes.Equal(peerKey, path[0].NoisePublicKey) {
			noiseConn.Close()
			return nil, fmt.Errorf("entry relay Noise key mismatch")
		}
	}

	// Send entry token
	if err := noiseConn.Send(token.MarshalToken(tokens[0])); err != nil {
		noiseConn.Close()
		return nil, fmt.Errorf("send token: %w", err)
	}
	resp, err := noiseConn.Recv()
	if err != nil || len(resp) < 1 || resp[0] != 0x01 {
		noiseConn.Close()
		return nil, fmt.Errorf("entry token rejected")
	}

	// Build the onion-wrapped blob from exit inward
	onionBlob, err := buildOnionBlob(path, tokens, destAddr)
	if err != nil {
		noiseConn.Close()
		return nil, fmt.Errorf("build onion: %w", err)
	}

	// Send the onion blob through the Noise channel
	if err := noiseConn.Send(onionBlob); err != nil {
		noiseConn.Close()
		return nil, fmt.Errorf("send onion: %w", err)
	}

	circuitID := m.nextID.Add(1)
	circ := &Circuit{
		ID:        circuitID,
		Path:      path,
		EntryConn: noiseConn,
		CreatedAt: time.Now(),
	}

	m.mu.Lock()
	m.circuits[circuitID] = circ
	m.mu.Unlock()

	return circ, nil
}

// buildOnionBlob creates the multi-layered onion blob.
// Built from exit (innermost) to entry (outermost).
//
// Exit layer (encrypted with exit key):
//
//	[2-byte token_len][token][ExitInstruction(dest)]
//
// Middle layer (encrypted with middle key):
//
//	[2-byte token_len][token][ForwardInstruction(next_addr, encrypted_inner)]
//
// Entry layer (no token embedded — token sent via Noise):
//
//	ForwardInstruction(next_addr, encrypted_middle_blob) — or ExitInst if 1-hop
func buildOnionBlob(path []*directory.Relay, tokens []token.Token, destAddr string) ([]byte, error) {
	numHops := len(path)

	// Start with the exit node (innermost layer)
	exitIdx := numHops - 1
	exitInst := onion.EncodeInstruction(onion.Instruction{
		Type:    onion.InstructionExit,
		Address: destAddr,
	})

	// Embed token for exit relay
	var data []byte
	if exitIdx > 0 {
		// Exit is not the entry — embed token
		data = embedToken(tokens[exitIdx], exitInst)
	} else {
		// Single hop — exit IS entry, no embedded token needed
		data = exitInst
	}

	// Encrypt with exit relay's key
	wrapped, err := onion.Wrap(data, &path[exitIdx].PublicKey)
	if err != nil {
		return nil, fmt.Errorf("wrap exit layer: %w", err)
	}
	data = wrapped

	// Middle relays (from second-to-last back to second)
	for i := exitIdx - 1; i >= 1; i-- {
		fwdInst := onion.EncodeInstruction(onion.Instruction{
			Type:    onion.InstructionForward,
			Address: path[i+1].Address,
			Payload: data,
		})
		// Embed token for this relay
		withToken := embedToken(tokens[i], fwdInst)
		wrapped, err := onion.Wrap(withToken, &path[i].PublicKey)
		if err != nil {
			return nil, fmt.Errorf("wrap middle layer %d: %w", i, err)
		}
		data = wrapped
	}

	// Entry relay layer — token is sent via Noise, not embedded
	// Entry's instruction: forward to relay[1] with the remaining blob
	if numHops > 1 {
		entryInst := onion.EncodeInstruction(onion.Instruction{
			Type:    onion.InstructionForward,
			Address: path[1].Address,
			Payload: data,
		})
		wrapped, err := onion.Wrap(entryInst, &path[0].PublicKey)
		if err != nil {
			return nil, fmt.Errorf("wrap entry layer: %w", err)
		}
		data = wrapped
	}

	return data, nil
}

// embedToken prepends [2-byte token_len][token_bytes] to instruction data.
func embedToken(tok token.Token, instData []byte) []byte {
	tokenBytes := token.MarshalToken(tok)
	buf := make([]byte, 2+len(tokenBytes)+len(instData))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(tokenBytes)))
	copy(buf[2:2+len(tokenBytes)], tokenBytes)
	copy(buf[2+len(tokenBytes):], instData)
	return buf
}

// SendData sends data through the Noise channel to the entry relay.
func (c *Circuit) SendData(data []byte) error {
	if c.closed.Load() {
		return fmt.Errorf("circuit closed")
	}
	return c.EntryConn.Send(data)
}

// RecvData receives data from the circuit.
func (c *Circuit) RecvData() ([]byte, error) {
	if c.closed.Load() {
		return nil, fmt.Errorf("circuit closed")
	}
	return c.EntryConn.Recv()
}

// Close tears down the circuit.
func (c *Circuit) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	return c.EntryConn.Close()
}

func (m *Manager) CloseAll() {
	m.mu.Lock()
	circuits := make([]*Circuit, 0, len(m.circuits))
	for _, c := range m.circuits {
		circuits = append(circuits, c)
	}
	m.circuits = make(map[uint32]*Circuit)
	m.mu.Unlock()
	for _, c := range circuits {
		c.Close()
	}
}
