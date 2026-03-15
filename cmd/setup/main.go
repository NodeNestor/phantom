// Setup tool: generates all keys and config files for a local test network.
// Creates auth server key, N relay keys, and the directory file.
// Run this once to bootstrap everything.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/ludde/phantom/internal/directory"
	"github.com/ludde/phantom/internal/onion"
	"github.com/ludde/phantom/internal/token"
	"github.com/ludde/phantom/internal/transport"
)

func main() {
	numRelays := flag.Int("relays", 5, "number of relay nodes to generate")
	basePort := flag.Int("port", 9001, "starting port for relays")
	outDir := flag.String("out", "network", "output directory for config files")
	host := flag.String("host", "127.0.0.1", "host address for relays")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		log.Fatalf("create output dir: %v", err)
	}

	// Generate auth server key
	log.Println("generating auth server key...")
	privKey, err := token.GenerateSigningKey()
	if err != nil {
		log.Fatalf("generate auth key: %v", err)
	}
	signer := token.NewSigner(privKey)

	if err := os.WriteFile(filepath.Join(*outDir, "auth.key"), signer.PrivateKeyBytes(), 0600); err != nil {
		log.Fatalf("write auth key: %v", err)
	}
	pubBytes, _ := signer.PublicKeyBytes()
	if err := os.WriteFile(filepath.Join(*outDir, "auth.pub"), pubBytes, 0644); err != nil {
		log.Fatalf("write auth pubkey: %v", err)
	}

	// Generate relay keys and directory
	dir := directory.New()

	type relayJSON struct {
		OnionPrivateKey string `json:"onion_private_key"`
		OnionPublicKey  string `json:"onion_public_key"`
		NoisePrivateKey string `json:"noise_private_key"`
		NoisePublicKey  string `json:"noise_public_key"`
	}

	for i := 0; i < *numRelays; i++ {
		port := *basePort + i
		addr := fmt.Sprintf("%s:%d", *host, port)

		onionKP, err := onion.GenerateKeyPair()
		if err != nil {
			log.Fatalf("generate onion key %d: %v", i, err)
		}
		noiseKey, err := transport.GenerateStaticKey()
		if err != nil {
			log.Fatalf("generate noise key %d: %v", i, err)
		}

		id := directory.RelayID(onionKP.Public)

		// Determine role
		var role directory.RelayRole
		switch {
		case i == 0:
			role = directory.RoleGuard
		case i == *numRelays-1:
			role = directory.RoleExit
		default:
			role = directory.RoleAny
		}

		dir.Add(&directory.Relay{
			ID:        id,
			Address:   addr,
			PublicKey: onionKP.Public,
			Role:      role,
		})

		// Save relay config
		cfg := relayJSON{
			OnionPrivateKey: hex.EncodeToString(onionKP.Private[:]),
			OnionPublicKey:  hex.EncodeToString(onionKP.Public[:]),
			NoisePrivateKey: hex.EncodeToString(noiseKey.Private),
			NoisePublicKey:  hex.EncodeToString(noiseKey.Public),
		}
		cfgData, _ := json.MarshalIndent(cfg, "", "  ")
		cfgFile := filepath.Join(*outDir, fmt.Sprintf("relay-%d.json", i))
		if err := os.WriteFile(cfgFile, cfgData, 0600); err != nil {
			log.Fatalf("write relay config %d: %v", i, err)
		}

		isExit := ""
		if role == directory.RoleExit {
			isExit = " (EXIT)"
		}
		log.Printf("  relay %d: %s @ %s [%s]%s", i, id, addr, role, isExit)
	}

	// Save directory
	dirFile := filepath.Join(*outDir, "directory.json")
	if err := dir.SaveToFile(dirFile); err != nil {
		log.Fatalf("save directory: %v", err)
	}

	// Generate a random secret for auth
	secret := hex.EncodeToString([]byte("phantom-dev-secret-change-me!"))

	// Print startup commands
	fmt.Println("\n========================================")
	fmt.Println("  Phantom Network Setup Complete")
	fmt.Println("========================================")
	fmt.Printf("\nFiles generated in %s/\n\n", *outDir)
	fmt.Println("Start the network with these commands:")
	fmt.Println()
	fmt.Printf("  # 1. Auth server\n")
	fmt.Printf("  go run ./cmd/auth -key %s/auth.key -pubkey-out %s/auth.pub -secret %s\n\n",
		*outDir, *outDir, secret)
	fmt.Printf("  # 2. Relay nodes\n")
	for i := 0; i < *numRelays; i++ {
		port := *basePort + i
		exitFlag := ""
		if i == *numRelays-1 {
			exitFlag = " -exit"
		}
		fmt.Printf("  go run ./cmd/relay -listen :%d -config %s/relay-%d.json -pubkey %s/auth.pub%s\n",
			port, *outDir, i, *outDir, exitFlag)
	}
	fmt.Printf("\n  # 3. Client (SOCKS5 proxy)\n")
	fmt.Printf("  go run ./cmd/client -directory %s/directory.json -auth http://localhost:9000 -secret %s -hops 3\n\n",
		*outDir, secret)
	fmt.Println("  # 4. Test it")
	fmt.Println("  curl --socks5 127.0.0.1:1080 https://httpbin.org/ip")
	fmt.Println()
}
