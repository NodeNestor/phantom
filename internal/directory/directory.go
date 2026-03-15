// Package directory manages the list of known relays and random selection.
// Each relay has a public key (for onion encryption) and an address.
// The client uses this to build random circuits.
package directory

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sync"

	"github.com/ludde/phantom/internal/onion"
)

// Relay represents a known relay node.
type Relay struct {
	ID             string              `json:"id"`              // hex-encoded public key fingerprint
	Address        string              `json:"address"`         // host:port
	PublicKey      [onion.KeySize]byte `json:"public_key"`      // Curve25519 public key for onion encryption
	NoisePublicKey []byte              `json:"noise_public_key,omitempty"` // Noise static public key (optional, for verification)
	Role           RelayRole           `json:"role"`            // guard, middle, exit
}

// RelayRole determines what position a relay can serve in a circuit.
type RelayRole string

const (
	RoleGuard  RelayRole = "guard"  // entry node — knows client IP, not destination
	RoleMiddle RelayRole = "middle" // middle node — knows nothing
	RoleExit   RelayRole = "exit"   // exit node — knows destination, not client
	RoleAny    RelayRole = "any"    // can serve any role
)

// Directory holds all known relays and handles path selection.
type Directory struct {
	relays map[string]*Relay
	mu     sync.RWMutex
}

// New creates an empty directory.
func New() *Directory {
	return &Directory{
		relays: make(map[string]*Relay),
	}
}

// Add adds a relay to the directory.
func (d *Directory) Add(r *Relay) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.relays[r.ID] = r
}

// Remove removes a relay from the directory.
func (d *Directory) Remove(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.relays, id)
}

// Get returns a relay by ID.
func (d *Directory) Get(id string) (*Relay, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	r, ok := d.relays[id]
	return r, ok
}

// List returns all relays.
func (d *Directory) List() []*Relay {
	d.mu.RLock()
	defer d.mu.RUnlock()
	list := make([]*Relay, 0, len(d.relays))
	for _, r := range d.relays {
		list = append(list, r)
	}
	return list
}

// SelectPath picks a random circuit path of the given length.
// It tries to respect roles: first node is guard, last is exit, rest are middle.
// If not enough role-specific relays, it falls back to any available relay.
// No relay is used twice in the same path.
func (d *Directory) SelectPath(hops int) ([]*Relay, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if len(d.relays) < hops {
		return nil, fmt.Errorf("not enough relays: have %d, need %d", len(d.relays), hops)
	}

	// Categorize relays
	var guards, middles, exits []*Relay
	var all []*Relay
	for _, r := range d.relays {
		all = append(all, r)
		switch r.Role {
		case RoleGuard:
			guards = append(guards, r)
		case RoleMiddle:
			middles = append(middles, r)
		case RoleExit:
			exits = append(exits, r)
		case RoleAny:
			guards = append(guards, r)
			middles = append(middles, r)
			// RoleAny can serve as exit ONLY if no dedicated exit nodes exist
		}
	}

	used := make(map[string]bool)
	path := make([]*Relay, hops)

	// Pick guard (entry)
	guard, err := pickRandom(guards, used)
	if err != nil {
		guard, err = pickRandom(all, used)
		if err != nil {
			return nil, fmt.Errorf("no available guard relay")
		}
	}
	path[0] = guard
	used[guard.ID] = true

	// Pick exit (last)
	if hops > 1 {
		exit, err := pickRandom(exits, used)
		if err != nil {
			exit, err = pickRandom(all, used)
			if err != nil {
				return nil, fmt.Errorf("no available exit relay")
			}
		}
		path[hops-1] = exit
		used[exit.ID] = true
	}

	// Pick middles
	for i := 1; i < hops-1; i++ {
		middle, err := pickRandom(middles, used)
		if err != nil {
			middle, err = pickRandom(all, used)
			if err != nil {
				return nil, fmt.Errorf("no available middle relay for hop %d", i)
			}
		}
		path[i] = middle
		used[middle.ID] = true
	}

	return path, nil
}

// pickRandom selects a random relay from candidates, excluding already-used ones.
func pickRandom(candidates []*Relay, used map[string]bool) (*Relay, error) {
	var available []*Relay
	for _, r := range candidates {
		if !used[r.ID] {
			available = append(available, r)
		}
	}
	if len(available) == 0 {
		return nil, fmt.Errorf("no available relays")
	}

	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(available))))
	if err != nil {
		return nil, err
	}
	return available[idx.Int64()], nil
}

// RelayID generates a relay ID from its public key (128-bit fingerprint).
func RelayID(pubKey [onion.KeySize]byte) string {
	return hex.EncodeToString(pubKey[:16]) // first 16 bytes as hex
}

// --- Persistence ---

type directoryFile struct {
	Relays []relayJSON `json:"relays"`
}

type relayJSON struct {
	ID             string `json:"id"`
	Address        string `json:"address"`
	PublicKey      string `json:"public_key"`                 // hex-encoded
	NoisePublicKey string `json:"noise_public_key,omitempty"` // hex-encoded, optional
	Role           string `json:"role"`
}

// SaveToFile persists the directory to a JSON file.
func (d *Directory) SaveToFile(path string) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	df := directoryFile{}
	for _, r := range d.relays {
		rj := relayJSON{
			ID:        r.ID,
			Address:   r.Address,
			PublicKey: hex.EncodeToString(r.PublicKey[:]),
			Role:      string(r.Role),
		}
		if len(r.NoisePublicKey) > 0 {
			rj.NoisePublicKey = hex.EncodeToString(r.NoisePublicKey)
		}
		df.Relays = append(df.Relays, rj)
	}

	data, err := json.MarshalIndent(df, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// LoadFromFile loads the directory from a JSON file.
func (d *Directory) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var df directoryFile
	if err := json.Unmarshal(data, &df); err != nil {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	for _, rj := range df.Relays {
		pubKeyBytes, err := hex.DecodeString(rj.PublicKey)
		if err != nil {
			return fmt.Errorf("invalid public key for relay %s: %w", rj.ID, err)
		}
		var pubKey [onion.KeySize]byte
		copy(pubKey[:], pubKeyBytes)

		relay := &Relay{
			ID:        rj.ID,
			Address:   rj.Address,
			PublicKey: pubKey,
			Role:      RelayRole(rj.Role),
		}
		if rj.NoisePublicKey != "" {
			noiseKey, err := hex.DecodeString(rj.NoisePublicKey)
			if err != nil {
				return fmt.Errorf("invalid noise public key for relay %s: %w", rj.ID, err)
			}
			relay.NoisePublicKey = noiseKey
		}
		d.relays[rj.ID] = relay
	}
	return nil
}
