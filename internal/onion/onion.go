// Package onion implements layered encryption for multi-hop circuits.
// Each layer uses NaCl box (Curve25519 + XSalsa20-Poly1305).
// The client wraps N layers, each relay peels one.
package onion

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

const (
	// KeySize is the size of a Curve25519 key.
	KeySize = 32
	// NonceSize for NaCl box.
	NonceSize = 24
	// Overhead per layer: nonce + ephemeral pubkey + poly1305 tag.
	LayerOverhead = NonceSize + KeySize + box.Overhead
)

// KeyPair holds a Curve25519 key pair.
type KeyPair struct {
	Public  [KeySize]byte
	Private [KeySize]byte
}

// GenerateKeyPair creates a new random key pair.
func GenerateKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}
	if _, err := rand.Read(kp.Private[:]); err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}
	curve25519.ScalarBaseMult(&kp.Public, &kp.Private)
	return kp, nil
}

// Wrap encrypts payload with one onion layer for the given relay public key.
// Format: [ephemeral_pubkey (32)] [nonce (24)] [encrypted_data]
func Wrap(payload []byte, relayPubKey *[KeySize]byte) ([]byte, error) {
	// Generate ephemeral key pair for this layer
	ephemeral, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Encrypt with NaCl box: ephemeral private + relay public
	encrypted := box.Seal(nil, payload, &nonce, relayPubKey, &ephemeral.Private)

	// Prepend ephemeral public key and nonce
	result := make([]byte, 0, KeySize+NonceSize+len(encrypted))
	result = append(result, ephemeral.Public[:]...)
	result = append(result, nonce[:]...)
	result = append(result, encrypted...)
	return result, nil
}

// Unwrap decrypts one onion layer using the relay's private key.
// Returns the inner payload.
func Unwrap(data []byte, relayPrivKey *[KeySize]byte) ([]byte, error) {
	if len(data) < LayerOverhead {
		return nil, fmt.Errorf("data too short for onion layer: %d < %d", len(data), LayerOverhead)
	}

	var ephemeralPub [KeySize]byte
	copy(ephemeralPub[:], data[:KeySize])

	var nonce [NonceSize]byte
	copy(nonce[:], data[KeySize:KeySize+NonceSize])

	ciphertext := data[KeySize+NonceSize:]

	plaintext, ok := box.Open(nil, ciphertext, &nonce, &ephemeralPub, relayPrivKey)
	if !ok {
		return nil, fmt.Errorf("onion layer decryption failed (wrong key or tampered)")
	}
	return plaintext, nil
}

// WrapMulti wraps payload in multiple onion layers.
// relayKeys should be in order: [exit, middle, ..., entry]
// so the first key to encrypt is the exit (innermost), last is entry (outermost).
func WrapMulti(payload []byte, relayKeys []*[KeySize]byte) ([]byte, error) {
	data := payload
	for _, key := range relayKeys {
		wrapped, err := Wrap(data, key)
		if err != nil {
			return nil, fmt.Errorf("wrap layer: %w", err)
		}
		data = wrapped
	}
	return data, nil
}

// OnionInstruction is placed inside each layer to tell the relay what to do.
// Format: [1 byte type] [payload...]
//
//	Type 0x01 = Forward: [4 byte addr_len] [addr string] → forward to next relay
//	Type 0x02 = Exit:    [4 byte addr_len] [addr string] → connect to final destination
type InstructionType byte

const (
	InstructionForward InstructionType = 0x01
	InstructionExit    InstructionType = 0x02
)

// Instruction tells a relay what to do with the decrypted payload.
type Instruction struct {
	Type    InstructionType
	Address string // next hop or final destination (host:port)
	Payload []byte // remaining onion-wrapped data (or cleartext for exit)
}

// EncodeInstruction serializes an instruction for wrapping.
func EncodeInstruction(inst Instruction) []byte {
	addrBytes := []byte(inst.Address)
	// 1 byte type + 4 byte addr len + addr + payload
	buf := make([]byte, 1+4+len(addrBytes)+len(inst.Payload))
	buf[0] = byte(inst.Type)
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(addrBytes)))
	copy(buf[5:5+len(addrBytes)], addrBytes)
	copy(buf[5+len(addrBytes):], inst.Payload)
	return buf
}

// DecodeInstruction deserializes an instruction after unwrapping.
func DecodeInstruction(data []byte) (Instruction, error) {
	if len(data) < 5 {
		return Instruction{}, fmt.Errorf("instruction too short: %d", len(data))
	}
	inst := Instruction{
		Type: InstructionType(data[0]),
	}
	addrLen := binary.BigEndian.Uint32(data[1:5])
	if uint32(len(data)) < 5+addrLen {
		return Instruction{}, fmt.Errorf("instruction addr truncated")
	}
	inst.Address = string(data[5 : 5+addrLen])
	inst.Payload = data[5+addrLen:]
	return inst, nil
}
