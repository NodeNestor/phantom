package onion

import (
	"bytes"
	"testing"
)

func TestWrapUnwrap(t *testing.T) {
	// Generate relay key
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("hello from the other side")

	// Wrap
	wrapped, err := Wrap(payload, &kp.Public)
	if err != nil {
		t.Fatal(err)
	}

	// Should be bigger than payload (has overhead)
	if len(wrapped) <= len(payload) {
		t.Fatalf("wrapped should be larger: %d <= %d", len(wrapped), len(payload))
	}

	// Unwrap
	result, err := Unwrap(wrapped, &kp.Private)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(result, payload) {
		t.Fatalf("unwrap mismatch: got %q, want %q", result, payload)
	}
}

func TestWrapUnwrapMultiLayer(t *testing.T) {
	// 3 relays
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	kp3, _ := GenerateKeyPair()

	payload := []byte("secret message through 3 relays")

	// Wrap: exit first, entry last (reverse order)
	keys := []*[KeySize]byte{&kp3.Public, &kp2.Public, &kp1.Public}
	wrapped, err := WrapMulti(payload, keys)
	if err != nil {
		t.Fatal(err)
	}

	// Unwrap layer by layer: entry first
	layer1, err := Unwrap(wrapped, &kp1.Private)
	if err != nil {
		t.Fatalf("unwrap layer 1: %v", err)
	}

	layer2, err := Unwrap(layer1, &kp2.Private)
	if err != nil {
		t.Fatalf("unwrap layer 2: %v", err)
	}

	layer3, err := Unwrap(layer2, &kp3.Private)
	if err != nil {
		t.Fatalf("unwrap layer 3: %v", err)
	}

	if !bytes.Equal(layer3, payload) {
		t.Fatalf("3-layer unwrap mismatch: got %q, want %q", layer3, payload)
	}
}

func TestWrongKeyFails(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	wrapped, _ := Wrap([]byte("test"), &kp1.Public)

	// Try to unwrap with wrong key
	_, err := Unwrap(wrapped, &kp2.Private)
	if err == nil {
		t.Fatal("expected error when unwrapping with wrong key")
	}
}

func TestInstructionRoundTrip(t *testing.T) {
	inst := Instruction{
		Type:    InstructionForward,
		Address: "192.168.1.1:9001",
		Payload: []byte("encrypted-inner-data"),
	}

	encoded := EncodeInstruction(inst)
	decoded, err := DecodeInstruction(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if decoded.Type != inst.Type {
		t.Fatalf("type mismatch: %v != %v", decoded.Type, inst.Type)
	}
	if decoded.Address != inst.Address {
		t.Fatalf("address mismatch: %q != %q", decoded.Address, inst.Address)
	}
	if !bytes.Equal(decoded.Payload, inst.Payload) {
		t.Fatalf("payload mismatch")
	}
}
