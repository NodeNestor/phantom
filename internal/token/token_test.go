package token

import (
	"testing"
)

func TestBlindSignVerify(t *testing.T) {
	// Generate signing key (auth server)
	privKey, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	signer := NewSigner(privKey)

	// Get public key PEM (for relay)
	pubPEM, err := signer.PublicKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(pubPEM)
	if err != nil {
		t.Fatal(err)
	}

	// Client: create blinded token
	bt, err := Blind(&privKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Auth server: sign blinded token (never sees real token)
	blindSig, err := signer.SignBlinded(bt.Blinded)
	if err != nil {
		t.Fatal(err)
	}

	// Client: unblind to get final token
	tok := FinalizeToken(bt, blindSig, &privKey.PublicKey)

	// Relay: verify token
	if err := verifier.Verify(tok); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}

	// Relay: spend token
	if err := verifier.Spend(tok); err != nil {
		t.Fatalf("spend failed: %v", err)
	}

	// Relay: try to spend again (should fail)
	if err := verifier.Spend(tok); err == nil {
		t.Fatal("double-spend should fail")
	}
}

func TestForgedTokenRejected(t *testing.T) {
	privKey, _ := GenerateSigningKey()
	signer := NewSigner(privKey)
	pubPEM, _ := signer.PublicKeyBytes()
	verifier, _ := NewVerifier(pubPEM)

	// Create a fake token with garbage signature
	tok := Token{
		Value:     make([]byte, 32),
		Signature: []byte("this-is-not-a-valid-signature-at-all"),
	}

	err := verifier.Verify(tok)
	if err == nil {
		t.Fatal("forged token should be rejected")
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	privKey, _ := GenerateSigningKey()
	signer := NewSigner(privKey)

	bt, _ := Blind(&privKey.PublicKey)
	blindSig, _ := signer.SignBlinded(bt.Blinded)
	tok := FinalizeToken(bt, blindSig, &privKey.PublicKey)

	// Marshal
	data := MarshalToken(tok)

	// Unmarshal
	tok2, err := UnmarshalToken(data)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the unmarshaled token works
	pubPEM, _ := signer.PublicKeyBytes()
	verifier, _ := NewVerifier(pubPEM)
	if err := verifier.Verify(tok2); err != nil {
		t.Fatalf("unmarshaled token invalid: %v", err)
	}
}

func TestMultipleTokens(t *testing.T) {
	privKey, _ := GenerateSigningKey()
	signer := NewSigner(privKey)
	pubPEM, _ := signer.PublicKeyBytes()
	verifier, _ := NewVerifier(pubPEM)

	// Issue 10 tokens
	for i := 0; i < 10; i++ {
		bt, _ := Blind(&privKey.PublicKey)
		blindSig, _ := signer.SignBlinded(bt.Blinded)
		tok := FinalizeToken(bt, blindSig, &privKey.PublicKey)

		if err := verifier.Spend(tok); err != nil {
			t.Fatalf("token %d rejected: %v", i, err)
		}
	}
}
