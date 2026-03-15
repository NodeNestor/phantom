// Auth server: issues blind tokens to authorized users.
// It signs blinded token hashes without seeing the actual tokens.
// Run once, give the public key to all relays.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/ludde/phantom/internal/token"
)

func main() {
	listen := flag.String("listen", ":9000", "address to listen on")
	keyFile := flag.String("key", "auth.key", "path to RSA private key (created if missing)")
	pubFile := flag.String("pubkey-out", "auth.pub", "path to write public key")
	secret := flag.String("secret", "", "shared secret for token requests (required)")
	flag.Parse()

	// Prefer env var over CLI arg (CLI args visible in ps aux)
	if *secret == "" {
		*secret = os.Getenv("PHANTOM_SECRET")
	}
	if *secret == "" {
		fmt.Fprintln(os.Stderr, "error: -secret or PHANTOM_SECRET env var is required")
		os.Exit(1)
	}

	// Load or generate signing key
	var signer *token.Signer
	keyData, err := os.ReadFile(*keyFile)
	if err == nil {
		signer, err = token.LoadSignerFromPEM(keyData)
		if err != nil {
			log.Fatalf("load key: %v", err)
		}
		log.Printf("loaded signing key from %s", *keyFile)
	} else {
		log.Printf("generating new signing key...")
		privKey, err := token.GenerateSigningKey()
		if err != nil {
			log.Fatalf("generate key: %v", err)
		}
		signer = token.NewSigner(privKey)
		if err := os.WriteFile(*keyFile, signer.PrivateKeyBytes(), 0600); err != nil {
			log.Fatalf("save key: %v", err)
		}
		log.Printf("saved signing key to %s", *keyFile)
	}

	// Write public key for relays
	pubBytes, err := signer.PublicKeyBytes()
	if err != nil {
		log.Fatalf("export public key: %v", err)
	}
	if err := os.WriteFile(*pubFile, pubBytes, 0644); err != nil {
		log.Fatalf("save public key: %v", err)
	}
	log.Printf("public key written to %s", *pubFile)

	// HTTP API for token signing
	mux := http.NewServeMux()

	mux.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}

		// Check auth
		if r.Header.Get("Authorization") != "Bearer "+*secret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var req struct {
			BlindedTokens []string `json:"blinded_tokens"` // hex-encoded blinded hashes
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		if len(req.BlindedTokens) > 100 {
			http.Error(w, "max 100 tokens per request", http.StatusBadRequest)
			return
		}

		var signatures []string
		for _, blindedHex := range req.BlindedTokens {
			blinded, err := hex.DecodeString(blindedHex)
			if err != nil {
				http.Error(w, "invalid hex in blinded token", http.StatusBadRequest)
				return
			}

			sig, err := signer.SignBlinded(blinded)
			if err != nil {
				log.Printf("sign error: %v", err)
				http.Error(w, "signing failed", http.StatusInternalServerError)
				return
			}
			signatures = append(signatures, hex.EncodeToString(sig))
		}

		log.Printf("signed %d tokens for client", len(signatures))

		json.NewEncoder(w).Encode(map[string]any{
			"signatures": signatures,
		})
	})

	// Endpoint to get the public key
	mux.HandleFunc("/pubkey", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(pubBytes)
	})

	log.Printf("auth server listening on %s", *listen)
	if err := http.ListenAndServe(*listen, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
