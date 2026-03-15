// Relay node: accepts onion-encrypted traffic, peels one layer, forwards.
// Zero trust — knows nothing about the client or final destination.
// Verifies blind tokens to prevent abuse without identifying users.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ludde/phantom/internal/onion"
	"github.com/ludde/phantom/internal/relay"
	"github.com/ludde/phantom/internal/token"
	"github.com/ludde/phantom/internal/transport"
)

type relayConfig struct {
	OnionPrivateKey string `json:"onion_private_key"` // hex
	OnionPublicKey  string `json:"onion_public_key"`  // hex
	NoisePrivateKey string `json:"noise_private_key"` // hex
	NoisePublicKey  string `json:"noise_public_key"`  // hex
}

func main() {
	listen := flag.String("listen", ":9001", "address to listen on")
	pubKeyFile := flag.String("pubkey", "auth.pub", "path to auth server public key (PEM)")
	configFile := flag.String("config", "relay.json", "relay config file (created if missing)")
	exit := flag.Bool("exit", false, "allow exit connections to the internet")
	flag.Parse()

	// Load auth public key for token verification
	pubKeyPEM, err := os.ReadFile(*pubKeyFile)
	if err != nil {
		log.Fatalf("load auth public key: %v", err)
	}
	verifier, err := token.NewVerifier(pubKeyPEM)
	if err != nil {
		log.Fatalf("create verifier: %v", err)
	}

	// Load or generate relay keys
	var onionKP *onion.KeyPair
	var noiseKey *transport.StaticKey

	cfgData, err := os.ReadFile(*configFile)
	if err == nil {
		var cfg relayConfig
		if err := json.Unmarshal(cfgData, &cfg); err != nil {
			log.Fatalf("parse config: %v", err)
		}
		onionKP = &onion.KeyPair{}
		privBytes, _ := hex.DecodeString(cfg.OnionPrivateKey)
		pubBytes, _ := hex.DecodeString(cfg.OnionPublicKey)
		copy(onionKP.Private[:], privBytes)
		copy(onionKP.Public[:], pubBytes)

		noisePriv, _ := hex.DecodeString(cfg.NoisePrivateKey)
		noisePub, _ := hex.DecodeString(cfg.NoisePublicKey)
		noiseKey = &transport.StaticKey{Private: noisePriv, Public: noisePub}

		log.Printf("loaded keys from %s", *configFile)
	} else {
		log.Printf("generating new relay keys...")
		onionKP, err = onion.GenerateKeyPair()
		if err != nil {
			log.Fatalf("generate onion key: %v", err)
		}
		noiseKey, err = transport.GenerateStaticKey()
		if err != nil {
			log.Fatalf("generate noise key: %v", err)
		}

		cfg := relayConfig{
			OnionPrivateKey: hex.EncodeToString(onionKP.Private[:]),
			OnionPublicKey:  hex.EncodeToString(onionKP.Public[:]),
			NoisePrivateKey: hex.EncodeToString(noiseKey.Private),
			NoisePublicKey:  hex.EncodeToString(noiseKey.Public),
		}
		data, _ := json.MarshalIndent(cfg, "", "  ")
		if err := os.WriteFile(*configFile, data, 0600); err != nil {
			log.Fatalf("save config: %v", err)
		}
		log.Printf("saved keys to %s", *configFile)
	}

	fmt.Printf("\n  Relay ID:         %s\n", hex.EncodeToString(onionKP.Public[:8]))
	fmt.Printf("  Onion Public Key: %s\n", hex.EncodeToString(onionKP.Public[:]))
	fmt.Printf("  Noise Public Key: %s\n", hex.EncodeToString(noiseKey.Public))
	fmt.Printf("  Exit node:        %v\n\n", *exit)

	// Start relay
	srv := relay.New(relay.Config{
		ListenAddr: *listen,
		OnionKey:   onionKP,
		NoiseKey:   noiseKey,
		Verifier:   verifier,
		IsExit:     *exit,
	})

	if err := srv.Start(); err != nil {
		log.Fatalf("start relay: %v", err)
	}

	// Wait for shutdown signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("shutting down...")
	srv.Stop()
}
