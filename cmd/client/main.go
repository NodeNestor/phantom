// Client: local SOCKS5 proxy that routes traffic through random onion circuits.
// Each new connection gets a fresh random circuit with N hops.
package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
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
	"syscall"

	"github.com/ludde/phantom/internal/circuit"
	"github.com/ludde/phantom/internal/directory"
	"github.com/ludde/phantom/internal/token"
	"github.com/ludde/phantom/internal/transport"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	dirFile := flag.String("directory", "directory.json", "relay directory file")
	hops := flag.Int("hops", 3, "number of relay hops per circuit")
	authURL := flag.String("auth", "", "auth server URL (e.g., http://localhost:9000)")
	authSecret := flag.String("secret", "", "auth server secret")
	tokenCount := flag.Int("tokens", 50, "number of tokens to request")
	flag.Parse()

	dir := directory.New()
	if err := dir.LoadFromFile(*dirFile); err != nil {
		log.Fatalf("load directory: %v", err)
	}
	relays := dir.List()
	log.Printf("loaded %d relays from %s", len(relays), *dirFile)
	for _, r := range relays {
		log.Printf("  relay %s @ %s (role=%s)", r.ID, r.Address, r.Role)
	}
	if len(relays) < *hops {
		log.Fatalf("need at least %d relays, have %d", *hops, len(relays))
	}

	noiseKey, err := transport.GenerateStaticKey()
	if err != nil {
		log.Fatalf("generate noise key: %v", err)
	}

	if *authURL == "" {
		log.Fatalf("-auth is required")
	}
	tokens, err := fetchTokens(*authURL, *authSecret, *tokenCount)
	if err != nil {
		log.Fatalf("fetch tokens: %v", err)
	}
	log.Printf("obtained %d anonymous tokens", len(tokens))

	mgr := circuit.NewManager(dir, *hops, noiseKey)
	mgr.SetTokens(tokens)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("SOCKS5 proxy listening on %s (%d-hop circuits)", *listen, *hops)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					log.Printf("accept: %v", err)
					continue
				}
			}
			go handleSOCKS5(conn, mgr)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("shutting down, %d tokens remaining", mgr.TokenCount())
	cancel()
	ln.Close()
	mgr.CloseAll()
}

func handleSOCKS5(conn net.Conn, mgr *circuit.Manager) {
	defer conn.Close()

	buf := make([]byte, 256)

	// SOCKS5 greeting
	n, err := conn.Read(buf)
	if err != nil || n < 3 || buf[0] != 0x05 {
		return
	}
	conn.Write([]byte{0x05, 0x00}) // no auth

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

	log.Printf("[socks5] CONNECT %s", destAddr)

	// Build circuit with destination baked into the onion
	circ, err := mgr.BuildCircuit(destAddr)
	if err != nil {
		log.Printf("[socks5] circuit failed: %v", err)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	pathStr := make([]string, len(circ.Path))
	for i, r := range circ.Path {
		pathStr[i] = r.ID[:8]
	}
	log.Printf("[socks5] circuit %d: you -> %s -> %s", circ.ID, strings.Join(pathStr, " -> "), destAddr)

	// SOCKS5 success
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Bidirectional relay: SOCKS5 client <-> circuit (Noise channel)
	// Both directions must complete for clean shutdown
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Circuit
	go func() {
		defer wg.Done()
		buf := make([]byte, 64*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if circ.SendData(buf[:n]) != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
	}()

	// Circuit -> Client
	go func() {
		defer wg.Done()
		for {
			data, err := circ.RecvData()
			if err != nil {
				break
			}
			if _, err := conn.Write(data); err != nil {
				break
			}
		}
		// Half-close the write side so the client knows we're done
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
	circ.Close()
}

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

	// Batch requests in chunks of 100 (auth server limit)
	var allTokens []token.Token
	for start := 0; start < count; start += 100 {
		batchSize := count - start
		if batchSize > 100 {
			batchSize = 100
		}

		batch, err := fetchTokenBatch(authURL, secret, rsaPub, batchSize)
		if err != nil {
			return nil, fmt.Errorf("batch at %d: %w", start, err)
		}
		allTokens = append(allTokens, batch...)
	}
	return allTokens, nil
}

func fetchTokenBatch(authURL, secret string, rsaPub *rsa.PublicKey, count int) ([]token.Token, error) {
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

	reqBody, _ := json.Marshal(map[string]any{"blinded_tokens": blindedHexes})
	req, _ := http.NewRequest("POST", authURL+"/sign", strings.NewReader(string(reqBody)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+secret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("sign failed (%d): %s", resp.StatusCode, body)
	}

	var signResp struct {
		Signatures []string `json:"signatures"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&signResp); err != nil {
		return nil, fmt.Errorf("decode sigs: %w", err)
	}

	tokens := make([]token.Token, count)
	for i := 0; i < count; i++ {
		sigBytes, _ := hex.DecodeString(signResp.Signatures[i])
		tokens[i] = token.FinalizeToken(blindedTokens[i], sigBytes, rsaPub)
	}
	return tokens, nil
}
