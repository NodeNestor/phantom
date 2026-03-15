// Package token implements blind RSA tokens for zero-trust authentication.
// The auth server signs blinded tokens — it can never link a token to a user.
// Relays verify tokens with the public key and track spent tokens.
package token

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
)

// Token is an anonymous auth token: a random value + its blind signature.
type Token struct {
	Value     []byte // random 32-byte token
	Signature []byte // RSA signature (unblinded)
}

// BlindedToken is what the client sends to the auth server for signing.
type BlindedToken struct {
	Blinded  []byte // blinded hash
	Unblinder *big.Int // client keeps this secret to unblind later
	Original []byte // original token value (client keeps secret)
}

// Signer is the auth server's token issuer.
type Signer struct {
	key *rsa.PrivateKey
}

// Verifier is used by relays to check tokens.
type Verifier struct {
	pubKey    *rsa.PublicKey
	spent     map[string]bool
	spentLock sync.RWMutex
}

// NewSigner creates a signer from an RSA private key.
func NewSigner(key *rsa.PrivateKey) *Signer {
	return &Signer{key: key}
}

// GenerateSigningKey creates a new 2048-bit RSA key for token signing.
func GenerateSigningKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// PublicKeyBytes returns the PEM-encoded public key for distribution to relays.
func (s *Signer) PublicKeyBytes() ([]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(&s.key.PublicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}), nil
}

// PrivateKeyBytes returns the PEM-encoded private key for storage.
func (s *Signer) PrivateKeyBytes() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(s.key),
	})
}

// LoadSignerFromPEM loads a signer from PEM-encoded private key.
func LoadSignerFromPEM(data []byte) (*Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &Signer{key: key}, nil
}

// --- Client-side: blind, unblind ---

// Blind creates a blinded token that the client sends to the auth server.
// The auth server signs it without ever seeing the real token.
func Blind(pubKey *rsa.PublicKey) (*BlindedToken, error) {
	// Generate random token value
	tokenValue := make([]byte, 32)
	if _, err := rand.Read(tokenValue); err != nil {
		return nil, err
	}

	// Hash the token
	hash := sha256.Sum256(tokenValue)

	// Blind the hash
	// r = random blinding factor, coprime to N
	// blinded = hash * r^e mod N
	r, err := rand.Int(rand.Reader, pubKey.N)
	if err != nil {
		return nil, err
	}
	// Make sure r is coprime to N
	for new(big.Int).GCD(nil, nil, r, pubKey.N).Cmp(big.NewInt(1)) != 0 {
		r, err = rand.Int(rand.Reader, pubKey.N)
		if err != nil {
			return nil, err
		}
	}

	e := big.NewInt(int64(pubKey.E))
	// r^e mod N
	rE := new(big.Int).Exp(r, e, pubKey.N)
	// hash as big int
	hashInt := new(big.Int).SetBytes(hash[:])
	// blinded = hash * r^e mod N
	blinded := new(big.Int).Mul(hashInt, rE)
	blinded.Mod(blinded, pubKey.N)

	return &BlindedToken{
		Blinded:   blinded.Bytes(),
		Unblinder: r,
		Original:  tokenValue,
	}, nil
}

// Unblind removes the blinding factor from the server's signature.
func Unblind(blindSig []byte, unblinder *big.Int, pubKey *rsa.PublicKey) *Token {
	// sig = blindSig / r mod N = blindSig * r^-1 mod N
	blindSigInt := new(big.Int).SetBytes(blindSig)
	rInv := new(big.Int).ModInverse(unblinder, pubKey.N)
	sig := new(big.Int).Mul(blindSigInt, rInv)
	sig.Mod(sig, pubKey.N)

	// We don't return Original here because it's already in BlindedToken
	return &Token{
		Signature: sig.Bytes(),
	}
}

// FinalizeToken creates a complete token from the blinded token and unblinded signature.
func FinalizeToken(bt *BlindedToken, blindSig []byte, pubKey *rsa.PublicKey) Token {
	t := Unblind(blindSig, bt.Unblinder, pubKey)
	return Token{
		Value:     bt.Original,
		Signature: t.Signature,
	}
}

// --- Auth server side: sign blinded tokens ---

// SignBlinded signs a blinded token hash. The server never sees the actual token.
func (s *Signer) SignBlinded(blindedHash []byte) ([]byte, error) {
	// Raw RSA signature: blindedHash^d mod N
	m := new(big.Int).SetBytes(blindedHash)
	if m.Cmp(s.key.N) >= 0 {
		return nil, fmt.Errorf("blinded hash too large")
	}
	sig := new(big.Int).Exp(m, s.key.D, s.key.N)
	return sig.Bytes(), nil
}

// --- Relay side: verify and spend tokens ---

// NewVerifier creates a verifier from a PEM-encoded public key.
func NewVerifier(pubKeyPEM []byte) (*Verifier, error) {
	block, _ := pem.Decode(pubKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return &Verifier{
		pubKey: rsaPub,
		spent:  make(map[string]bool),
	}, nil
}

// Verify checks if a token has a valid signature and hasn't been spent.
func (v *Verifier) Verify(t Token) error {
	// Check if spent
	tokenID := hex.EncodeToString(t.Value)
	v.spentLock.RLock()
	if v.spent[tokenID] {
		v.spentLock.RUnlock()
		return fmt.Errorf("token already spent")
	}
	v.spentLock.RUnlock()

	// Verify signature: sig^e mod N should equal H(token)
	hash := sha256.Sum256(t.Value)
	hashInt := new(big.Int).SetBytes(hash[:])

	sigInt := new(big.Int).SetBytes(t.Signature)
	e := big.NewInt(int64(v.pubKey.E))
	recovered := new(big.Int).Exp(sigInt, e, v.pubKey.N)

	// Compare
	if recovered.Cmp(hashInt) != 0 {
		return fmt.Errorf("invalid token signature")
	}

	return nil
}

// Spend verifies and marks a token as spent. Returns error if invalid or already spent.
func (v *Verifier) Spend(t Token) error {
	if err := v.Verify(t); err != nil {
		return err
	}

	tokenID := hex.EncodeToString(t.Value)
	v.spentLock.Lock()
	defer v.spentLock.Unlock()

	// Double-check under write lock
	if v.spent[tokenID] {
		return fmt.Errorf("token already spent")
	}
	v.spent[tokenID] = true
	return nil
}

// PublicKey returns the verifier's public key (for client use).
func (v *Verifier) PublicKey() *rsa.PublicKey {
	return v.pubKey
}

// MarshalToken serializes a token for wire transmission.
func MarshalToken(t Token) []byte {
	// [32 bytes value] [remaining bytes signature]
	buf := make([]byte, 32+len(t.Signature))
	copy(buf[:32], t.Value)
	copy(buf[32:], t.Signature)
	return buf
}

// UnmarshalToken deserializes a token from wire format.
func UnmarshalToken(data []byte) (Token, error) {
	if len(data) < 33 { // at least 32 value + 1 sig byte
		return Token{}, fmt.Errorf("token data too short: %d", len(data))
	}
	return Token{
		Value:     data[:32],
		Signature: data[32:],
	}, nil
}

// Hash helper for external use.
func Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

var _ crypto.PublicKey = (*rsa.PublicKey)(nil) // compile check
