// Package relay implements the relay node server.
// A relay accepts two types of connections:
//   - Client connections (0x00 prefix): Noise handshake + token auth
//   - Relay-forwarded connections (0x01 prefix): raw onion blob with embedded token
//
// After authentication, it peels one onion layer and either forwards to the
// next relay or connects to the final destination (if exit node).
// All bidirectional relaying properly handles stream closure in both directions.
package relay

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/ludde/phantom/internal/onion"
	"github.com/ludde/phantom/internal/token"
	"github.com/ludde/phantom/internal/transport"
)

// blockedNets contains private/reserved IP ranges that exit nodes must not connect to.
var blockedNets = func() []*net.IPNet {
	cidrs := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"::1/128",
		"fe80::/10",
		"fc00::/7",
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("bad CIDR: " + cidr)
		}
		nets = append(nets, n)
	}
	return nets
}()

// isBlockedAddress resolves the hostname and checks all resolved IPs against
// private/reserved ranges. Returns true if any resolved IP is blocked.
func isBlockedAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return true // malformed address
	}

	// Try to parse as a literal IP first
	if ip := net.ParseIP(host); ip != nil {
		return isBlockedIP(ip)
	}

	// Resolve hostname
	ips, err := net.LookupIP(host)
	if err != nil {
		return true // can't resolve — block it
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return true
		}
	}
	return false
}

func isBlockedIP(ip net.IP) bool {
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

const (
	ConnTypeClient  byte = 0x00
	ConnTypeForward byte = 0x01

	relayBufSize    = 64 * 1024 // 64KB buffer for streaming
	dialTimeout     = 15 * time.Second
	keepAlivePeriod = 30 * time.Second
	handshakeTimeout = 15 * time.Second
	maxConcurrentConns = 1000
)

type Config struct {
	ListenAddr string
	OnionKey   *onion.KeyPair
	NoiseKey   *transport.StaticKey
	Verifier   *token.Verifier
	IsExit     bool
}

type Server struct {
	cfg      Config
	listener net.Listener
	wg       sync.WaitGroup
	quit     chan struct{}
	connSem  chan struct{} // semaphore limiting concurrent connections
}

func New(cfg Config) *Server {
	return &Server{
		cfg:     cfg,
		quit:    make(chan struct{}),
		connSem: make(chan struct{}, maxConcurrentConns),
	}
}

func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.listener = ln
	log.Printf("[relay] listening on %s (exit=%v)", s.cfg.ListenAddr, s.cfg.IsExit)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-s.quit:
					return
				default:
					log.Printf("[relay] accept error: %v", err)
					continue
				}
			}
			// Enable TCP keepalive for long-lived connections
			if tc, ok := conn.(*net.TCPConn); ok {
				tc.SetKeepAlive(true)
				tc.SetKeepAlivePeriod(keepAlivePeriod)
			}
			// Enforce max concurrent connection limit
			select {
			case s.connSem <- struct{}{}:
			default:
				log.Printf("[relay] max connections reached, rejecting %s", conn.RemoteAddr())
				conn.Close()
				continue
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer func() { <-s.connSem }()
				s.handleConnection(conn)
			}()
		}
	}()
	return nil
}

func (s *Server) Stop() {
	close(s.quit)
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
}

func (s *Server) handleConnection(rawConn net.Conn) {
	defer rawConn.Close()

	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(rawConn, typeBuf); err != nil {
		return
	}

	switch typeBuf[0] {
	case ConnTypeClient:
		s.handleClientConnection(rawConn)
	case ConnTypeForward:
		s.handleForwardedConnection(rawConn)
	default:
		log.Printf("[relay] unknown conn type 0x%02x from %s", typeBuf[0], rawConn.RemoteAddr())
	}
}

func (s *Server) handleClientConnection(rawConn net.Conn) {
	// Set handshake deadline
	rawConn.SetDeadline(time.Now().Add(handshakeTimeout))

	noiseConn, _, err := transport.AcceptHandshake(rawConn, s.cfg.NoiseKey)
	if err != nil {
		log.Printf("[relay] handshake failed from %s: %v", rawConn.RemoteAddr(), err)
		return
	}
	defer noiseConn.Close()

	// Clear deadline after successful handshake
	rawConn.SetDeadline(time.Time{})

	tokenData, err := noiseConn.Recv()
	if err != nil {
		return
	}
	tok, err := token.UnmarshalToken(tokenData)
	if err != nil {
		noiseConn.Send([]byte{0x00})
		return
	}
	if err := s.cfg.Verifier.Spend(tok); err != nil {
		log.Printf("[relay] token rejected: %v", err)
		noiseConn.Send([]byte{0x00})
		return
	}
	noiseConn.Send([]byte{0x01})
	log.Printf("[relay] client authenticated from %s", rawConn.RemoteAddr())

	data, err := noiseConn.Recv()
	if err != nil {
		log.Printf("[relay] recv onion data error: %v", err)
		return
	}

	decrypted, err := onion.Unwrap(data, &s.cfg.OnionKey.Private)
	if err != nil {
		log.Printf("[relay] onion unwrap failed: %v", err)
		return
	}

	inst, err := onion.DecodeInstruction(decrypted)
	if err != nil {
		log.Printf("[relay] invalid instruction: %v", err)
		return
	}

	switch inst.Type {
	case onion.InstructionForward:
		s.doForward(noiseConn, nil, inst, true)
	case onion.InstructionExit:
		if !s.cfg.IsExit {
			log.Printf("[relay] exit request but not an exit node")
			return
		}
		s.doExit(noiseConn, nil, inst, true)
	}
}

func (s *Server) handleForwardedConnection(rawConn net.Conn) {
	// Set handshake deadline
	rawConn.SetDeadline(time.Now().Add(handshakeTimeout))

	// Accept Noise handshake from the forwarding relay
	noiseConn, _, err := transport.AcceptHandshake(rawConn, s.cfg.NoiseKey)
	if err != nil {
		log.Printf("[relay] forward noise handshake failed: %v", err)
		return
	}
	defer noiseConn.Close()

	// Clear deadline after successful handshake
	rawConn.SetDeadline(time.Time{})

	// Receive the onion blob over the encrypted Noise channel
	blob, err := noiseConn.Recv()
	if err != nil {
		return
	}

	if len(blob) > 1<<20 {
		log.Printf("[relay] forward blob too large: %d", len(blob))
		return
	}

	decrypted, err := onion.Unwrap(blob, &s.cfg.OnionKey.Private)
	if err != nil {
		log.Printf("[relay] forward onion unwrap failed: %v", err)
		return
	}

	if len(decrypted) < 2 {
		return
	}
	tokenLen := binary.BigEndian.Uint16(decrypted[:2])
	if int(tokenLen)+2 > len(decrypted) {
		return
	}
	tokenData := decrypted[2 : 2+tokenLen]
	instData := decrypted[2+tokenLen:]

	tok, err := token.UnmarshalToken(tokenData)
	if err != nil {
		return
	}
	if err := s.cfg.Verifier.Spend(tok); err != nil {
		log.Printf("[relay] forward token rejected: %v", err)
		return
	}

	log.Printf("[relay] forwarded connection authenticated")

	inst, err := onion.DecodeInstruction(instData)
	if err != nil {
		return
	}

	switch inst.Type {
	case onion.InstructionForward:
		s.doForward(noiseConn, nil, inst, true)
	case onion.InstructionExit:
		if !s.cfg.IsExit {
			log.Printf("[relay] exit request but not an exit node")
			return
		}
		s.doExit(noiseConn, nil, inst, true)
	}
}

func (s *Server) doForward(prevNoise *transport.Conn, prevRaw net.Conn, inst onion.Instruction, useNoise bool) {
	nextConn, err := dialTCP(inst.Address)
	if err != nil {
		log.Printf("[relay] connect to next hop %s failed: %v", inst.Address, err)
		return
	}
	defer nextConn.Close()

	log.Printf("[relay] forwarding to next hop")

	// Send connection type prefix byte
	if _, err := nextConn.Write([]byte{ConnTypeForward}); err != nil {
		return
	}

	// Perform Noise handshake with the next relay
	nextNoiseConn, _, err := transport.Handshake(nextConn, s.cfg.NoiseKey)
	if err != nil {
		log.Printf("[relay] noise handshake to next hop failed: %v", err)
		return
	}
	defer nextNoiseConn.Close()

	// Send the onion blob over the encrypted Noise channel
	if err := nextNoiseConn.Send(inst.Payload); err != nil {
		return
	}

	// Bidirectional relay — wait for BOTH directions to finish
	if useNoise {
		relayNoiseToNoise(prevNoise, nextNoiseConn)
	} else {
		relayRawToNoise(prevRaw, nextNoiseConn)
	}
}

func (s *Server) doExit(prevNoise *transport.Conn, prevRaw net.Conn, inst onion.Instruction, useNoise bool) {
	if isBlockedAddress(inst.Address) {
		log.Printf("[relay] exit blocked: destination resolves to private/reserved IP")
		return
	}

	destConn, err := dialTCP(inst.Address)
	if err != nil {
		log.Printf("[relay] exit connect failed: %v", err)
		return
	}
	defer destConn.Close()

	log.Printf("[relay] exit connection established")

	if len(inst.Payload) > 0 {
		if _, err := destConn.Write(inst.Payload); err != nil {
			return
		}
	}

	if useNoise {
		relayNoiseToRaw(prevNoise, destConn)
	} else {
		relayRawToRaw(prevRaw, destConn)
	}
}

// relayNoiseToRaw copies data bidirectionally between a Noise connection and a raw TCP connection.
// Properly closes both directions when either side finishes.
func relayNoiseToRaw(noiseConn *transport.Conn, rawConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Raw -> Noise
	go func() {
		defer wg.Done()
		buf := make([]byte, relayBufSize)
		for {
			n, err := rawConn.Read(buf)
			if n > 0 {
				if noiseConn.Send(buf[:n]) != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		// Signal the Noise side that we're done reading from raw
		// Close the raw read side to unblock any pending Noise->Raw writes
		if tc, ok := rawConn.(*net.TCPConn); ok {
			tc.CloseRead()
		}
	}()

	// Noise -> Raw
	go func() {
		defer wg.Done()
		for {
			data, err := noiseConn.Recv()
			if err != nil {
				break
			}
			if _, err := rawConn.Write(data); err != nil {
				break
			}
		}
		// Signal the raw side that we're done writing
		if tc, ok := rawConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
}

// relayNoiseToNoise copies data bidirectionally between two Noise connections.
func relayNoiseToNoise(a, b *transport.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for {
			data, err := a.Recv()
			if err != nil {
				break
			}
			if b.Send(data) != nil {
				break
			}
		}
	}()

	go func() {
		defer wg.Done()
		for {
			data, err := b.Recv()
			if err != nil {
				break
			}
			if a.Send(data) != nil {
				break
			}
		}
	}()

	wg.Wait()
}

// relayRawToNoise copies data bidirectionally between a raw TCP connection and a Noise connection.
func relayRawToNoise(rawConn net.Conn, noiseConn *transport.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Raw -> Noise
	go func() {
		defer wg.Done()
		buf := make([]byte, relayBufSize)
		for {
			n, err := rawConn.Read(buf)
			if n > 0 {
				if noiseConn.Send(buf[:n]) != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		if tc, ok := rawConn.(*net.TCPConn); ok {
			tc.CloseRead()
		}
	}()

	// Noise -> Raw
	go func() {
		defer wg.Done()
		for {
			data, err := noiseConn.Recv()
			if err != nil {
				break
			}
			if _, err := rawConn.Write(data); err != nil {
				break
			}
		}
		if tc, ok := rawConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
}

// relayRawToRaw copies data bidirectionally between two raw TCP connections.
// Uses io.Copy for maximum throughput on streams.
func relayRawToRaw(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(b, a)
		if tc, ok := b.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(a, b)
		if tc, ok := a.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
}

// dialTCP connects to an address with timeout and keepalive.
func dialTCP(addr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(keepAlivePeriod)
		tc.SetNoDelay(true)
	}
	return conn, nil
}

func (s *Server) Addr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}
