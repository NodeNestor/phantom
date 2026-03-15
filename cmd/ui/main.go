// Phantom VPN — Web UI
// Serves a single-page web interface on localhost:3000 for managing the VPN client.
// Embeds the HTML/CSS/JS in the binary, no external dependencies.
package main

import (
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ludde/phantom/internal/circuit"
	"github.com/ludde/phantom/internal/directory"
	"github.com/ludde/phantom/internal/onion"
	"github.com/ludde/phantom/internal/token"
	"github.com/ludde/phantom/internal/transport"
)

//go:embed index.html
var embedFS embed.FS

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

type Settings struct {
	Hops           int    `json:"hops"`
	AuthURL        string `json:"auth_url"`
	AuthSecret     string `json:"auth_secret,omitempty"`
	DirectoryFile  string `json:"directory_file"`
	AutoReconnect  bool   `json:"auto_reconnect"`
	SOCKSListen    string `json:"socks_listen"`
	TokenCount     int    `json:"token_count"`
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

type Stats struct {
	Connected      bool   `json:"connected"`
	Hops           int    `json:"hops"`
	UptimeSeconds  int64  `json:"uptime_seconds"`
	CircuitsBuilt  int64  `json:"circuits_built"`
	BytesSent      int64  `json:"bytes_sent"`
	BytesRecv      int64  `json:"bytes_recv"`
	TokensRemain   int    `json:"tokens_remaining"`
	MaxTokens      int    `json:"max_tokens"`
	CircuitPath    []RelayInfo `json:"circuit_path"`
}

type RelayInfo struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	Role    string `json:"role"`
}

// ---------------------------------------------------------------------------
// Log entry
// ---------------------------------------------------------------------------

type LogEntry struct {
	Time    time.Time `json:"time"`
	Message string    `json:"message"`
	Level   string    `json:"level"` // info, success, warning, error
}

// ---------------------------------------------------------------------------
// WebSocket message
// ---------------------------------------------------------------------------

type WSMessage struct {
	Type string      `json:"type"` // status, relays, settings, log
	Data interface{} `json:"data"`
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

type App struct {
	settings    Settings
	settingsMu  sync.RWMutex

	dir         *directory.Directory
	mgr         *circuit.Manager
	noiseKey    *transport.StaticKey

	connected   atomic.Bool
	connectedAt time.Time
	connectMu   sync.Mutex

	circuitsBuilt atomic.Int64
	bytesSent     atomic.Int64
	bytesRecv     atomic.Int64
	maxTokens     int

	socksListener net.Listener
	socksCancel   context.CancelFunc

	// Auth server (runs in-process)
	authSigner   *token.Signer
	authServer   *http.Server
	authRunning  atomic.Bool
	authKeyFile  string
	authPubFile  string

	logs   []LogEntry
	logsMu sync.RWMutex

	wsClients   map[*wsConn]bool
	wsClientsMu sync.Mutex
}

func newApp(settings Settings) *App {
	return &App{
		settings:  settings,
		maxTokens: settings.TokenCount,
		wsClients: make(map[*wsConn]bool),
	}
}

func (a *App) addLog(msg, level string) {
	entry := LogEntry{Time: time.Now(), Message: msg, Level: level}
	a.logsMu.Lock()
	a.logs = append(a.logs, entry)
	if len(a.logs) > 500 {
		a.logs = a.logs[len(a.logs)-500:]
	}
	a.logsMu.Unlock()
	log.Printf("[%s] %s", level, msg)
	a.broadcast(WSMessage{Type: "log", Data: entry})
}

func (a *App) getStatus() Stats {
	a.settingsMu.RLock()
	hops := a.settings.Hops
	a.settingsMu.RUnlock()

	s := Stats{
		Connected:     a.connected.Load(),
		Hops:          hops,
		CircuitsBuilt: a.circuitsBuilt.Load(),
		BytesSent:     a.bytesSent.Load(),
		BytesRecv:     a.bytesRecv.Load(),
		MaxTokens:     a.maxTokens,
	}

	if s.Connected {
		s.UptimeSeconds = int64(time.Since(a.connectedAt).Seconds())
	}

	if a.mgr != nil {
		s.TokensRemain = a.mgr.TokenCount()
	}

	// Get current circuit path info from directory
	if a.dir != nil && s.Connected {
		relays := a.dir.List()
		if len(relays) > 0 {
			// Show up to hops relays as the "current path" representation
			count := hops
			if count > len(relays) {
				count = len(relays)
			}
			s.CircuitPath = make([]RelayInfo, count)
			for i := 0; i < count; i++ {
				role := string(relays[i].Role)
				if i == 0 {
					role = "guard"
				} else if i == count-1 {
					role = "exit"
				} else {
					role = "middle"
				}
				s.CircuitPath[i] = RelayInfo{
					ID:      relays[i].ID,
					Address: relays[i].Address,
					Role:    role,
				}
			}
		}
	}

	return s
}

func (a *App) getRelays() []RelayInfo {
	if a.dir == nil {
		return nil
	}
	relays := a.dir.List()
	result := make([]RelayInfo, len(relays))
	for i, r := range relays {
		result[i] = RelayInfo{
			ID:      r.ID,
			Address: r.Address,
			Role:    string(r.Role),
		}
	}
	return result
}

func (a *App) broadcastStatus() {
	a.broadcast(WSMessage{Type: "status", Data: a.getStatus()})
}

// ---------------------------------------------------------------------------
// Connect / Disconnect
// ---------------------------------------------------------------------------

func (a *App) connect() error {
	a.connectMu.Lock()
	defer a.connectMu.Unlock()

	if a.connected.Load() {
		return fmt.Errorf("already connected")
	}

	a.settingsMu.RLock()
	settings := a.settings
	a.settingsMu.RUnlock()

	a.addLog("Loading relay directory from "+settings.DirectoryFile, "info")

	dir := directory.New()
	if err := dir.LoadFromFile(settings.DirectoryFile); err != nil {
		return fmt.Errorf("load directory: %w", err)
	}
	a.dir = dir

	relays := dir.List()
	a.addLog(fmt.Sprintf("Loaded %d relays", len(relays)), "success")
	for _, r := range relays {
		a.addLog(fmt.Sprintf("  Relay %s @ %s (role=%s)", r.ID, r.Address, r.Role), "info")
	}

	if len(relays) < settings.Hops {
		return fmt.Errorf("need at least %d relays, have %d", settings.Hops, len(relays))
	}

	// Broadcast relay list
	a.broadcast(WSMessage{Type: "relays", Data: a.getRelays()})

	noiseKey, err := transport.GenerateStaticKey()
	if err != nil {
		return fmt.Errorf("generate noise key: %w", err)
	}
	a.noiseKey = noiseKey

	if settings.AuthURL == "" {
		return fmt.Errorf("auth server URL is required")
	}

	a.addLog("Requesting tokens from auth server...", "info")
	tokens, err := fetchTokens(settings.AuthURL, settings.AuthSecret, settings.TokenCount)
	if err != nil {
		return fmt.Errorf("fetch tokens: %w", err)
	}
	a.maxTokens = len(tokens)
	a.addLog(fmt.Sprintf("Obtained %d anonymous tokens", len(tokens)), "success")

	mgr := circuit.NewManager(dir, settings.Hops, noiseKey)
	mgr.SetTokens(tokens)
	a.mgr = mgr

	// Start SOCKS5 proxy
	ln, err := net.Listen("tcp", settings.SOCKSListen)
	if err != nil {
		return fmt.Errorf("listen SOCKS5: %w", err)
	}
	a.socksListener = ln

	ctx, cancel := context.WithCancel(context.Background())
	a.socksCancel = cancel

	a.connected.Store(true)
	a.connectedAt = time.Now()
	a.circuitsBuilt.Store(0)
	a.bytesSent.Store(0)
	a.bytesRecv.Store(0)

	a.addLog(fmt.Sprintf("SOCKS5 proxy listening on %s (%d-hop circuits)", settings.SOCKSListen, settings.Hops), "success")
	a.broadcastStatus()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					a.addLog(fmt.Sprintf("Accept error: %v", err), "warning")
					continue
				}
			}
			go a.handleSOCKS5(conn)
		}
	}()

	// Periodic status broadcast
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if a.connected.Load() {
					a.broadcastStatus()
				}
			}
		}
	}()

	return nil
}

func (a *App) disconnect() error {
	a.connectMu.Lock()
	defer a.connectMu.Unlock()

	if !a.connected.Load() {
		return fmt.Errorf("not connected")
	}

	a.addLog("Disconnecting...", "warning")

	a.connected.Store(false)

	if a.socksCancel != nil {
		a.socksCancel()
	}
	if a.socksListener != nil {
		a.socksListener.Close()
	}
	if a.mgr != nil {
		a.mgr.CloseAll()
		a.addLog(fmt.Sprintf("Closed all circuits, %d tokens remaining", a.mgr.TokenCount()), "info")
	}

	a.addLog("Disconnected", "success")
	a.broadcastStatus()
	return nil
}

// ---------------------------------------------------------------------------
// SOCKS5 proxy handler (adapted from cmd/client)
// ---------------------------------------------------------------------------

func (a *App) handleSOCKS5(conn net.Conn) {
	defer conn.Close()

	// SOCKS5 greeting: read version + nmethods
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil || header[0] != 0x05 {
		return
	}
	nMethods := int(header[1])
	if nMethods < 1 {
		return
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	conn.Write([]byte{0x05, 0x00}) // no auth

	// SOCKS5 connect request: read VER, CMD, RSV, ATYP
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return
	}
	if reqHeader[1] != 0x01 { // only CONNECT
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var destAddr string
	switch reqHeader[3] {
	case 0x01: // IPv4
		addrBuf := make([]byte, 4+2) // 4 IP + 2 port
		if _, err := io.ReadFull(conn, addrBuf); err != nil {
			return
		}
		destAddr = fmt.Sprintf("%d.%d.%d.%d:%d", addrBuf[0], addrBuf[1], addrBuf[2], addrBuf[3],
			uint16(addrBuf[4])<<8|uint16(addrBuf[5]))
	case 0x03: // Domain
		domLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, domLenBuf); err != nil {
			return
		}
		domLen := int(domLenBuf[0])
		domAndPort := make([]byte, domLen+2)
		if _, err := io.ReadFull(conn, domAndPort); err != nil {
			return
		}
		port := uint16(domAndPort[domLen])<<8 | uint16(domAndPort[domLen+1])
		destAddr = fmt.Sprintf("%s:%d", string(domAndPort[:domLen]), port)
	case 0x04: // IPv6
		addrBuf := make([]byte, 16+2) // 16 IP + 2 port
		if _, err := io.ReadFull(conn, addrBuf); err != nil {
			return
		}
		ip := net.IP(addrBuf[:16])
		port := uint16(addrBuf[16])<<8 | uint16(addrBuf[17])
		destAddr = fmt.Sprintf("[%s]:%d", ip.String(), port)
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	a.addLog(fmt.Sprintf("CONNECT %s", destAddr), "info")

	circ, err := a.mgr.BuildCircuit(destAddr)
	if err != nil {
		a.addLog(fmt.Sprintf("Circuit failed: %v", err), "error")
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

		// Auto-reconnect on token exhaustion
		a.settingsMu.RLock()
		autoReconnect := a.settings.AutoReconnect
		a.settingsMu.RUnlock()
		if autoReconnect && a.mgr.TokenCount() == 0 {
			go func() {
				a.addLog("Tokens exhausted, auto-reconnecting...", "warning")
				a.disconnect()
				time.Sleep(time.Second)
				if err := a.connect(); err != nil {
					a.addLog(fmt.Sprintf("Auto-reconnect failed: %v", err), "error")
				}
			}()
		}
		return
	}

	a.circuitsBuilt.Add(1)
	pathStr := make([]string, len(circ.Path))
	for i, r := range circ.Path {
		pathStr[i] = r.ID[:8]
	}
	a.addLog(fmt.Sprintf("Circuit %d: you -> %s -> %s", circ.ID, strings.Join(pathStr, " -> "), destAddr), "success")
	a.broadcastStatus()

	// SOCKS5 success
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Bidirectional relay
	done := make(chan struct{}, 2)

	// Client -> Circuit
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				a.bytesSent.Add(int64(n))
				if circ.SendData(buf[:n]) != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()

	// Circuit -> Client
	go func() {
		for {
			data, err := circ.RecvData()
			if err != nil {
				break
			}
			a.bytesRecv.Add(int64(len(data)))
			if _, err := conn.Write(data); err != nil {
				break
			}
		}
		done <- struct{}{}
	}()

	<-done
	circ.Close()
}

// ---------------------------------------------------------------------------
// Token fetching (adapted from cmd/client)
// ---------------------------------------------------------------------------

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
	rsaPub := pub.(*rsa.PublicKey)

	blindedTokens := make([]*token.BlindedToken, count)
	blindedHexes := make([]string, count)
	for i := 0; i < count; i++ {
		bt, err := token.Blind(rsaPub)
		if err != nil {
			return nil, fmt.Errorf("blind token %d: %w", i, err)
		}
		blindedTokens[i] = bt
		blindedHexes[i] = hex.EncodeToString(bt.Blinded)
	}

	reqBody, _ := json.Marshal(map[string]interface{}{"blinded_tokens": blindedHexes})
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

// ---------------------------------------------------------------------------
// Minimal WebSocket implementation (RFC 6455) — no external dependency
// ---------------------------------------------------------------------------

type wsConn struct {
	conn    net.Conn
	writeMu sync.Mutex
	closed  atomic.Bool
}

func upgradeWebSocket(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, fmt.Errorf("not a websocket request")
	}

	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, fmt.Errorf("missing Sec-WebSocket-Key")
	}

	// Compute accept key per RFC 6455
	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-5AB5DC11548B"))
	acceptKey := base64.StdEncoding.EncodeToString(h.Sum(nil))

	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("server doesn't support hijacking")
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey + "\r\n\r\n"

	if _, err := bufrw.WriteString(resp); err != nil {
		conn.Close()
		return nil, err
	}
	if err := bufrw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}

	return &wsConn{conn: conn}, nil
}

func (ws *wsConn) writeMessage(data []byte) error {
	ws.writeMu.Lock()
	defer ws.writeMu.Unlock()

	if ws.closed.Load() {
		return fmt.Errorf("closed")
	}

	// Text frame, opcode 0x81
	var frame []byte
	payloadLen := len(data)

	if payloadLen < 126 {
		frame = make([]byte, 2+payloadLen)
		frame[0] = 0x81
		frame[1] = byte(payloadLen)
		copy(frame[2:], data)
	} else if payloadLen < 65536 {
		frame = make([]byte, 4+payloadLen)
		frame[0] = 0x81
		frame[1] = 126
		binary.BigEndian.PutUint16(frame[2:4], uint16(payloadLen))
		copy(frame[4:], data)
	} else {
		frame = make([]byte, 10+payloadLen)
		frame[0] = 0x81
		frame[1] = 127
		binary.BigEndian.PutUint64(frame[2:10], uint64(payloadLen))
		copy(frame[10:], data)
	}

	ws.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := ws.conn.Write(frame)
	return err
}

func (ws *wsConn) readFrame() (opcode byte, payload []byte, err error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(ws.conn, header); err != nil {
		return 0, nil, err
	}

	opcode = header[0] & 0x0F
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7F)

	if length == 126 {
		ext := make([]byte, 2)
		if _, err := io.ReadFull(ws.conn, ext); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext))
	} else if length == 127 {
		ext := make([]byte, 8)
		if _, err := io.ReadFull(ws.conn, ext); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext)
	}

	if length > 1<<20 {
		return 0, nil, fmt.Errorf("frame too large")
	}

	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(ws.conn, mask[:]); err != nil {
			return 0, nil, err
		}
	}

	payload = make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(ws.conn, payload); err != nil {
			return 0, nil, err
		}
	}

	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}

	return opcode, payload, nil
}

func (ws *wsConn) close() {
	if ws.closed.Swap(true) {
		return
	}
	// Send close frame
	ws.writeMu.Lock()
	closeFrame := []byte{0x88, 0x02, 0x03, 0xe8} // 1000 normal closure
	ws.conn.SetWriteDeadline(time.Now().Add(time.Second))
	ws.conn.Write(closeFrame)
	ws.writeMu.Unlock()
	ws.conn.Close()
}

// ---------------------------------------------------------------------------
// Broadcast to all WebSocket clients
// ---------------------------------------------------------------------------

func (a *App) broadcast(msg WSMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	a.wsClientsMu.Lock()
	clients := make([]*wsConn, 0, len(a.wsClients))
	for c := range a.wsClients {
		clients = append(clients, c)
	}
	a.wsClientsMu.Unlock()

	for _, c := range clients {
		if err := c.writeMessage(data); err != nil {
			a.wsClientsMu.Lock()
			delete(a.wsClients, c)
			a.wsClientsMu.Unlock()
			c.close()
		}
	}
}

// ---------------------------------------------------------------------------
// HTTP Handlers
// ---------------------------------------------------------------------------

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	data, err := embedFS.ReadFile("index.html")
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func (a *App) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a.getStatus())
}

func (a *App) handleConnect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := a.connect(); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "connected"})
}

func (a *App) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := a.disconnect(); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "disconnected"})
}

func (a *App) handleRelays(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	relays := a.getRelays()
	if relays == nil {
		relays = []RelayInfo{}
	}
	json.NewEncoder(w).Encode(relays)
}

func (a *App) handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	a.logsMu.RLock()
	logs := make([]LogEntry, len(a.logs))
	copy(logs, a.logs)
	a.logsMu.RUnlock()
	json.NewEncoder(w).Encode(logs)
}

func (a *App) handleSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "GET" {
		a.settingsMu.RLock()
		s := a.settings
		a.settingsMu.RUnlock()
		s.AuthSecret = "" // don't send secret to frontend
		json.NewEncoder(w).Encode(s)
		return
	}

	var update struct {
		Hops          *int    `json:"hops"`
		AuthURL       *string `json:"auth_url"`
		DirectoryFile *string `json:"directory_file"`
		AutoReconnect *bool   `json:"auto_reconnect"`
	}
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	a.settingsMu.Lock()
	if update.Hops != nil && *update.Hops >= 2 && *update.Hops <= 5 {
		a.settings.Hops = *update.Hops
	}
	if update.AuthURL != nil {
		a.settings.AuthURL = *update.AuthURL
	}
	if update.DirectoryFile != nil {
		a.settings.DirectoryFile = *update.DirectoryFile
	}
	if update.AutoReconnect != nil {
		a.settings.AutoReconnect = *update.AutoReconnect
	}
	settings := a.settings
	a.settingsMu.Unlock()

	a.addLog("Settings updated", "success")

	settings.AuthSecret = ""
	a.broadcast(WSMessage{Type: "settings", Data: settings})
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (a *App) handleWS(w http.ResponseWriter, r *http.Request) {
	ws, err := upgradeWebSocket(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	a.wsClientsMu.Lock()
	a.wsClients[ws] = true
	a.wsClientsMu.Unlock()

	// Send initial state
	statusData, _ := json.Marshal(WSMessage{Type: "status", Data: a.getStatus()})
	ws.writeMessage(statusData)

	relays := a.getRelays()
	if relays == nil {
		relays = []RelayInfo{}
	}
	relayData, _ := json.Marshal(WSMessage{Type: "relays", Data: relays})
	ws.writeMessage(relayData)

	a.settingsMu.RLock()
	s := a.settings
	a.settingsMu.RUnlock()
	s.AuthSecret = ""
	settData, _ := json.Marshal(WSMessage{Type: "settings", Data: s})
	ws.writeMessage(settData)

	// Read loop (just to detect close / handle pings)
	for {
		opcode, _, err := ws.readFrame()
		if err != nil {
			break
		}
		switch opcode {
		case 0x08: // close
			goto done
		case 0x09: // ping — respond with pong
			ws.writeMu.Lock()
			pong := []byte{0x8A, 0x00}
			ws.conn.Write(pong)
			ws.writeMu.Unlock()
		}
	}

done:
	a.wsClientsMu.Lock()
	delete(a.wsClients, ws)
	a.wsClientsMu.Unlock()
	ws.close()
}

// ---------------------------------------------------------------------------
// Auth Server Management
// ---------------------------------------------------------------------------

func (a *App) handleAuthStart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if a.authRunning.Load() {
		json.NewEncoder(w).Encode(map[string]string{"error": "auth server already running"})
		return
	}

	var req struct {
		Listen string `json:"listen"`
		Secret string `json:"secret"`
	}
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&req)
	}
	if req.Listen == "" {
		req.Listen = ":9000"
	}
	if req.Secret == "" {
		req.Secret = a.settings.AuthSecret
	}
	if req.Secret == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "secret is required"})
		return
	}

	// Load or generate signing key
	keyFile := "auth.key"
	pubFile := "auth.pub"
	a.authKeyFile = keyFile
	a.authPubFile = pubFile

	var signer *token.Signer
	keyData, err := os.ReadFile(keyFile)
	if err == nil {
		signer, err = token.LoadSignerFromPEM(keyData)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": "load key: " + err.Error()})
			return
		}
		a.addLog("Loaded auth signing key from "+keyFile, "info")
	} else {
		a.addLog("Generating new auth signing key...", "info")
		privKey, err := token.GenerateSigningKey()
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": "generate key: " + err.Error()})
			return
		}
		signer = token.NewSigner(privKey)
		if err := os.WriteFile(keyFile, signer.PrivateKeyBytes(), 0600); err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": "save key: " + err.Error()})
			return
		}
		a.addLog("Saved signing key to "+keyFile, "success")
	}

	pubBytes, _ := signer.PublicKeyBytes()
	os.WriteFile(pubFile, pubBytes, 0644)
	a.authSigner = signer

	// Start HTTP server for token signing
	mux := http.NewServeMux()
	secret := req.Secret

	mux.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+secret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var signReq struct {
			BlindedTokens []string `json:"blinded_tokens"`
		}
		if err := json.NewDecoder(r.Body).Decode(&signReq); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if len(signReq.BlindedTokens) > 100 {
			http.Error(w, "max 100 tokens per request", http.StatusBadRequest)
			return
		}
		var signatures []string
		for _, blindedHex := range signReq.BlindedTokens {
			blinded, err := hex.DecodeString(blindedHex)
			if err != nil {
				http.Error(w, "invalid hex", http.StatusBadRequest)
				return
			}
			sig, err := signer.SignBlinded(blinded)
			if err != nil {
				http.Error(w, "sign error", http.StatusInternalServerError)
				return
			}
			signatures = append(signatures, hex.EncodeToString(sig))
		}
		json.NewEncoder(w).Encode(map[string]any{"signatures": signatures})
	})

	mux.HandleFunc("/pubkey", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(pubBytes)
	})

	a.authServer = &http.Server{Addr: req.Listen, Handler: mux}
	a.authRunning.Store(true)

	go func() {
		a.addLog(fmt.Sprintf("Auth server started on %s", req.Listen), "success")
		if err := a.authServer.ListenAndServe(); err != http.ErrServerClosed {
			a.addLog(fmt.Sprintf("Auth server error: %v", err), "error")
		}
		a.authRunning.Store(false)
	}()

	json.NewEncoder(w).Encode(map[string]any{
		"status":   "running",
		"listen":   req.Listen,
		"key_file": keyFile,
		"pub_file": pubFile,
	})
}

func (a *App) handleAuthStop(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !a.authRunning.Load() {
		json.NewEncoder(w).Encode(map[string]string{"error": "auth server not running"})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	a.authServer.Shutdown(ctx)
	a.authRunning.Store(false)
	a.addLog("Auth server stopped", "warning")
	json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

func (a *App) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"running":  a.authRunning.Load(),
		"key_file": a.authKeyFile,
		"pub_file": a.authPubFile,
	})
}

// ---------------------------------------------------------------------------
// Relay Management
// ---------------------------------------------------------------------------

func (a *App) handleAddRelay(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		Address string `json:"address"`
		Role    string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Address == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "address is required"})
		return
	}
	if req.Role == "" {
		req.Role = "any"
	}

	// Generate a placeholder key — real key comes from the relay itself
	// For now, generate a random key pair to represent this relay
	kp, err := onion.GenerateKeyPair()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "generate key: " + err.Error()})
		return
	}

	id := directory.RelayID(kp.Public)
	relay := &directory.Relay{
		ID:        id,
		Address:   req.Address,
		PublicKey: kp.Public,
		Role:      directory.RelayRole(req.Role),
	}

	if a.dir == nil {
		a.dir = directory.New()
	}
	a.dir.Add(relay)

	// Save to file
	a.settingsMu.RLock()
	dirFile := a.settings.DirectoryFile
	a.settingsMu.RUnlock()
	if dirFile != "" {
		a.dir.SaveToFile(dirFile)
	}

	a.addLog(fmt.Sprintf("Added relay %s @ %s (role=%s)", id, req.Address, req.Role), "success")
	a.broadcast(WSMessage{Type: "relays", Data: a.getRelays()})
	json.NewEncoder(w).Encode(map[string]any{
		"status": "added",
		"id":     id,
		"pubkey": hex.EncodeToString(kp.Public[:]),
	})
}

func (a *App) handleRemoveRelay(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "id is required"})
		return
	}
	if a.dir == nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "no directory loaded"})
		return
	}
	a.dir.Remove(req.ID)

	a.settingsMu.RLock()
	dirFile := a.settings.DirectoryFile
	a.settingsMu.RUnlock()
	if dirFile != "" {
		a.dir.SaveToFile(dirFile)
	}

	a.addLog(fmt.Sprintf("Removed relay %s", req.ID), "warning")
	a.broadcast(WSMessage{Type: "relays", Data: a.getRelays()})
	json.NewEncoder(w).Encode(map[string]string{"status": "removed"})
}

func (a *App) handleDeployScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req struct {
		OS   string `json:"os"`   // linux, darwin, windows
		Arch string `json:"arch"` // amd64, arm64, armv7
		Port string `json:"port"`
		Exit bool   `json:"exit"`
	}
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&req)
	}
	if req.OS == "" {
		req.OS = "linux"
	}
	if req.Arch == "" {
		req.Arch = "amd64"
	}
	if req.Port == "" {
		req.Port = "9001"
	}

	ext := ""
	if req.OS == "windows" {
		ext = ".exe"
	}
	exitFlag := ""
	if req.Exit {
		exitFlag = " -exit"
	}

	script := fmt.Sprintf(`#!/bin/bash
# Phantom Relay Setup — %s/%s
# Run this on the relay machine

# 1. Download the relay binary
# (Copy phantom-relay%s to this machine)

# 2. Copy auth.pub from your auth server
# scp your-auth-server:auth.pub .

# 3. Start the relay
./phantom-relay%s -listen :%s -pubkey auth.pub%s

# The relay will print its ID and public key.
# Add those to your directory.json file.
`, req.OS, req.Arch, ext, ext, req.Port, exitFlag)

	json.NewEncoder(w).Encode(map[string]string{"script": script})
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:3000", "Web UI listen address")
	socksAddr := flag.String("socks", "127.0.0.1:1080", "SOCKS5 proxy listen address")
	dirFile := flag.String("directory", "directory.json", "Relay directory file")
	hops := flag.Int("hops", 3, "Number of relay hops (2-5)")
	authURL := flag.String("auth", "", "Auth server URL")
	authSecret := flag.String("secret", "", "Auth server secret")
	tokenCount := flag.Int("tokens", 50, "Number of tokens to request")
	flag.Parse()

	settings := Settings{
		Hops:          *hops,
		AuthURL:       *authURL,
		AuthSecret:    *authSecret,
		DirectoryFile: *dirFile,
		SOCKSListen:   *socksAddr,
		TokenCount:    *tokenCount,
	}

	app := newApp(settings)

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleIndex)
	mux.HandleFunc("/api/status", app.handleStatus)
	mux.HandleFunc("/api/connect", app.handleConnect)
	mux.HandleFunc("/api/disconnect", app.handleDisconnect)
	mux.HandleFunc("/api/relays", app.handleRelays)
	mux.HandleFunc("/api/logs", app.handleLogs)
	mux.HandleFunc("/api/settings", app.handleSettings)
	mux.HandleFunc("/api/auth/start", app.handleAuthStart)
	mux.HandleFunc("/api/auth/stop", app.handleAuthStop)
	mux.HandleFunc("/api/auth/status", app.handleAuthStatus)
	mux.HandleFunc("/api/relays/add", app.handleAddRelay)
	mux.HandleFunc("/api/relays/remove", app.handleRemoveRelay)
	mux.HandleFunc("/api/relays/deploy", app.handleDeployScript)
	mux.HandleFunc("/ws", app.handleWS)

	server := &http.Server{
		Addr:    *listenAddr,
		Handler: mux,
	}

	app.addLog(fmt.Sprintf("Phantom VPN UI starting on http://%s", *listenAddr), "info")

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
	if app.connected.Load() {
		app.disconnect()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)
}
