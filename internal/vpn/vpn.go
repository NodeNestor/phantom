// Package vpn orchestrates the VPN mode: starts a local SOCKS5 proxy,
// configures system-wide proxy settings to route all traffic through it,
// auto-refreshes tokens, and tracks connection status.
package vpn

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ludde/phantom/internal/circuit"
	"github.com/ludde/phantom/internal/directory"
	"github.com/ludde/phantom/internal/sysproxy"
	"github.com/ludde/phantom/internal/token"
	"github.com/ludde/phantom/internal/transport"
)

// Config holds the settings needed to start VPN mode.
type Config struct {
	// ListenAddr is the local SOCKS5 address (default "127.0.0.1:1080").
	ListenAddr string
	// Hops is the number of relay hops per circuit.
	Hops int
	// AuthURL is the auth server URL for fetching tokens.
	AuthURL string
	// AuthSecret is the bearer token for the auth server.
	AuthSecret string
	// TokenBatch is how many tokens to fetch per request.
	TokenBatch int
	// TokenRefreshThreshold triggers a refresh when tokens drop below this.
	TokenRefreshThreshold int
	// Directory is the relay directory.
	Directory *directory.Directory
}

// Status contains the current VPN state, safe to read from any goroutine.
type Status struct {
	Connected     bool          `json:"connected"`
	Uptime        time.Duration `json:"uptime"`
	CircuitCount  int           `json:"circuit_count"`
	TokensLeft    int           `json:"tokens_left"`
	BytesIn       uint64        `json:"bytes_in"`
	BytesOut      uint64        `json:"bytes_out"`
	ListenAddr    string        `json:"listen_addr"`
	ProxyEnabled  bool          `json:"proxy_enabled"`
}

// VPN is the main VPN mode orchestrator.
type VPN struct {
	cfg       Config
	mgr       *circuit.Manager
	noiseKey  *transport.StaticKey
	listener  net.Listener
	startTime time.Time

	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64
	circuits atomic.Int32

	proxyEnabled bool
	proxyMu      sync.Mutex

	cancel context.CancelFunc
	done   chan struct{}
}

// New creates a new VPN instance. Call Connect() to start.
func New(cfg Config) (*VPN, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:1080"
	}
	if cfg.Hops == 0 {
		cfg.Hops = 3
	}
	if cfg.TokenBatch == 0 {
		cfg.TokenBatch = 50
	}
	if cfg.TokenRefreshThreshold == 0 {
		cfg.TokenRefreshThreshold = 10
	}

	noiseKey, err := transport.GenerateStaticKey()
	if err != nil {
		return nil, fmt.Errorf("generate noise key: %w", err)
	}

	mgr := circuit.NewManager(cfg.Directory, cfg.Hops, noiseKey)

	return &VPN{
		cfg:      cfg,
		mgr:      mgr,
		noiseKey: noiseKey,
		done:     make(chan struct{}),
	}, nil
}

// Connect starts the SOCKS5 proxy, sets system proxy, and begins serving.
func (v *VPN) Connect(ctx context.Context) error {
	// Fetch initial tokens
	tokens, err := fetchTokens(v.cfg.AuthURL, v.cfg.AuthSecret, v.cfg.TokenBatch)
	if err != nil {
		return fmt.Errorf("fetch initial tokens: %w", err)
	}
	v.mgr.SetTokens(tokens)
	log.Printf("[vpn] obtained %d anonymous tokens", len(tokens))

	// Start SOCKS5 listener
	ln, err := net.Listen("tcp", v.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", v.cfg.ListenAddr, err)
	}
	v.listener = ln

	// Parse the listen address to get host and port for system proxy
	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		ln.Close()
		return fmt.Errorf("parse listen addr: %w", err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		ln.Close()
		return fmt.Errorf("parse port: %w", err)
	}

	// Set system proxy
	if err := sysproxy.Enable(host, port); err != nil {
		log.Printf("[vpn] warning: could not set system proxy: %v", err)
		log.Printf("[vpn] traffic will only be routed if apps use SOCKS5 at %s", v.cfg.ListenAddr)
	} else {
		v.proxyMu.Lock()
		v.proxyEnabled = true
		v.proxyMu.Unlock()
		log.Printf("[vpn] system proxy set to socks5://%s:%d", host, port)
	}

	v.startTime = time.Now()

	ctx, cancel := context.WithCancel(ctx)
	v.cancel = cancel

	// Token auto-refresh goroutine
	go v.tokenRefreshLoop(ctx)

	// Accept loop
	go v.acceptLoop(ctx)

	log.Printf("[vpn] connected — SOCKS5 on %s, %d-hop circuits", v.cfg.ListenAddr, v.cfg.Hops)
	return nil
}

// Disconnect tears down the VPN: restores proxy, closes circuits, stops listener.
func (v *VPN) Disconnect() {
	if v.cancel != nil {
		v.cancel()
	}

	// Restore system proxy settings
	v.proxyMu.Lock()
	wasEnabled := v.proxyEnabled
	v.proxyEnabled = false
	v.proxyMu.Unlock()

	if wasEnabled {
		if err := sysproxy.Disable(); err != nil {
			log.Printf("[vpn] warning: could not restore system proxy: %v", err)
		} else {
			log.Printf("[vpn] system proxy restored")
		}
	}

	// Close listener
	if v.listener != nil {
		v.listener.Close()
	}

	// Close all circuits
	v.mgr.CloseAll()

	log.Printf("[vpn] disconnected, %d tokens remaining", v.mgr.TokenCount())
}

// GetStatus returns a snapshot of the current VPN state.
func (v *VPN) GetStatus() Status {
	v.proxyMu.Lock()
	proxyOn := v.proxyEnabled
	v.proxyMu.Unlock()

	connected := v.cancel != nil && v.listener != nil
	var uptime time.Duration
	if connected && !v.startTime.IsZero() {
		uptime = time.Since(v.startTime)
	}

	return Status{
		Connected:    connected,
		Uptime:       uptime,
		CircuitCount: int(v.circuits.Load()),
		TokensLeft:   v.mgr.TokenCount(),
		BytesIn:      v.bytesIn.Load(),
		BytesOut:     v.bytesOut.Load(),
		ListenAddr:   v.cfg.ListenAddr,
		ProxyEnabled: proxyOn,
	}
}

// acceptLoop accepts incoming SOCKS5 connections and handles them.
func (v *VPN) acceptLoop(ctx context.Context) {
	for {
		conn, err := v.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("[vpn] accept error: %v", err)
				continue
			}
		}
		go v.handleSOCKS5(ctx, conn)
	}
}

// tokenRefreshLoop checks token levels and fetches more when running low.
func (v *VPN) tokenRefreshLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			count := v.mgr.TokenCount()
			if count < v.cfg.TokenRefreshThreshold {
				log.Printf("[vpn] tokens low (%d), refreshing...", count)
				tokens, err := fetchTokens(v.cfg.AuthURL, v.cfg.AuthSecret, v.cfg.TokenBatch)
				if err != nil {
					log.Printf("[vpn] token refresh failed: %v", err)
					continue
				}
				v.mgr.SetTokens(tokens)
				log.Printf("[vpn] refreshed %d tokens, now %d available", len(tokens), v.mgr.TokenCount())
			}
		}
	}
}

// handleSOCKS5 handles a single SOCKS5 connection, building a circuit
// and relaying data bidirectionally.
func (v *VPN) handleSOCKS5(_ context.Context, conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 256)

	// SOCKS5 greeting
	n, err := conn.Read(buf)
	if err != nil || n < 3 || buf[0] != 0x05 {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// SOCKS5 connect request
	n, err = conn.Read(buf)
	if err != nil || n < 7 || buf[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var destAddr string
	switch buf[3] {
	case 0x01: // IPv4
		if n < 10 {
			return
		}
		destAddr = fmt.Sprintf("%d.%d.%d.%d:%d", buf[4], buf[5], buf[6], buf[7],
			uint16(buf[8])<<8|uint16(buf[9]))
	case 0x03: // Domain
		domLen := int(buf[4])
		if n < 5+domLen+2 {
			return
		}
		port := uint16(buf[5+domLen])<<8 | uint16(buf[5+domLen+1])
		destAddr = fmt.Sprintf("%s:%d", string(buf[5:5+domLen]), port)
	case 0x04: // IPv6
		if n < 22 {
			return
		}
		ip := net.IP(buf[4:20])
		port := uint16(buf[20])<<8 | uint16(buf[21])
		destAddr = fmt.Sprintf("[%s]:%d", ip.String(), port)
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	log.Printf("[vpn] CONNECT %s", destAddr)

	// Build circuit
	circ, err := v.mgr.BuildCircuit(destAddr)
	if err != nil {
		log.Printf("[vpn] circuit failed for %s: %v", destAddr, err)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	v.circuits.Add(1)
	defer v.circuits.Add(-1)

	pathStr := make([]string, len(circ.Path))
	for i, r := range circ.Path {
		pathStr[i] = r.ID[:8]
	}
	log.Printf("[vpn] circuit %d: you -> %s -> %s", circ.ID, strings.Join(pathStr, " -> "), destAddr)

	// SOCKS5 success
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Bidirectional relay with byte counting
	done := make(chan struct{}, 2)

	// Client -> Circuit
	go func() {
		b := make([]byte, 32*1024)
		for {
			nr, rerr := conn.Read(b)
			if nr > 0 {
				v.bytesOut.Add(uint64(nr))
				if circ.SendData(b[:nr]) != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		done <- struct{}{}
	}()

	// Circuit -> Client
	go func() {
		for {
			data, rerr := circ.RecvData()
			if rerr != nil {
				break
			}
			v.bytesIn.Add(uint64(len(data)))
			if _, werr := conn.Write(data); werr != nil {
				break
			}
		}
		done <- struct{}{}
	}()

	<-done
	circ.Close()
}

// fetchTokens requests blind tokens from the auth server.
func fetchTokens(authURL, secret string, count int) ([]token.Token, error) {
	resp, err := http.Get(authURL + "/pubkey")
	if err != nil {
		return nil, fmt.Errorf("get pubkey: %w", err)
	}
	defer resp.Body.Close()
	pubKeyPEM, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read pubkey: %w", err)
	}

	block, _ := pem.Decode(pubKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pubkey: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	blindedTokens := make([]*token.BlindedToken, count)
	blindedHexes := make([]string, count)
	for i := 0; i < count; i++ {
		bt, berr := token.Blind(rsaPub)
		if berr != nil {
			return nil, fmt.Errorf("blind token %d: %w", i, berr)
		}
		blindedTokens[i] = bt
		blindedHexes[i] = hex.EncodeToString(bt.Blinded)
	}

	reqBody, _ := json.Marshal(map[string]any{"blinded_tokens": blindedHexes})
	req, _ := http.NewRequest("POST", authURL+"/sign", strings.NewReader(string(reqBody)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+secret)

	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 {
		body, _ := io.ReadAll(resp2.Body)
		return nil, fmt.Errorf("sign failed (%d): %s", resp2.StatusCode, body)
	}

	var signResp struct {
		Signatures []string `json:"signatures"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&signResp); err != nil {
		return nil, fmt.Errorf("decode sigs: %w", err)
	}

	tokens := make([]token.Token, count)
	for i := 0; i < count; i++ {
		sigBytes, _ := hex.DecodeString(signResp.Signatures[i])
		tokens[i] = token.FinalizeToken(blindedTokens[i], sigBytes, rsaPub)
	}
	return tokens, nil
}
