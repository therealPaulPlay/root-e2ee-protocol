package rootproto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/hkdf"
)

// HKDF info string shared with the JS client
const hkdfInfo = "root-privacy-encryption"

// Session holds an AES-256-GCM cipher bound to a derived key
type Session struct {
	gcm cipher.AEAD
	mu  sync.Mutex
}

// Keypair holds raw P-256 public and private key bytes
// Public key: 65-byte uncompressed SEC1 (0x04 || X || Y)
// Private key: 32-byte raw scalar
type Keypair struct {
	PublicKey  []byte
	PrivateKey []byte
}

// GenerateKeypair creates a new P-256 keypair
func GenerateKeypair() (*Keypair, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Keypair{
		PublicKey:  priv.PublicKey().Bytes(),
		PrivateKey: priv.Bytes(),
	}, nil
}

// DeriveSharedSecret performs P-256 ECDH and runs HKDF-SHA256 over the result
// to produce a 32-byte AES key
func DeriveSharedSecret(yourPrivateKey, theirPublicKey []byte) ([]byte, error) {
	curve := ecdh.P256()

	priv, err := curve.NewPrivateKey(yourPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	pub, err := curve.NewPublicKey(theirPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	secret, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	reader := hkdf.New(sha256.New, secret, nil, []byte(hkdfInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// SessionFromKey builds an AES-GCM session from a 32-byte key
func SessionFromKey(key []byte) (*Session, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("shared secret must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Session{gcm: gcm}, nil
}

// Encrypt produces `nonce(12) || ciphertext || tag(16)`
func (s *Session) Encrypt(plaintext, aad []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return s.gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// Decrypt consumes `nonce(12) || ciphertext || tag(16)`
func (s *Session) Decrypt(ciphertext, aad []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nonceSize := s.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, body := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return s.gcm.Open(nil, nonce, body, aad)
}

// ComputeAAD binds envelope metadata to the ciphertext: SHA256(type|originId|targetId)
func ComputeAAD(msgType, originID, targetID string) []byte {
	h := sha256.Sum256([]byte(msgType + "|" + originID + "|" + targetID))
	return h[:]
}