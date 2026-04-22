package rootproto

import (
	"bytes"
	"testing"
)

func TestGenerateKeypair(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair error: %v", err)
	}
	if len(kp.PublicKey) != 65 || kp.PublicKey[0] != 0x04 {
		t.Errorf("public key must be 65-byte uncompressed SEC1 (leading 0x04), got %d bytes starting with %#x", len(kp.PublicKey), kp.PublicKey[0])
	}
	if len(kp.PrivateKey) != 32 {
		t.Errorf("private key must be a 32-byte scalar, got %d", len(kp.PrivateKey))
	}
}

func TestGenerateKeypairUnique(t *testing.T) {
	a, _ := GenerateKeypair()
	b, _ := GenerateKeypair()
	if bytes.Equal(a.PrivateKey, b.PrivateKey) || bytes.Equal(a.PublicKey, b.PublicKey) {
		t.Error("two generated keypairs should be distinct")
	}
}

func TestDeriveSharedSecretSymmetric(t *testing.T) {
	alice, _ := GenerateKeypair()
	bob, _ := GenerateKeypair()

	aliceSecret, err := deriveSharedSecret(alice.PrivateKey, bob.PublicKey)
	if err != nil {
		t.Fatalf("alice derive: %v", err)
	}
	bobSecret, err := deriveSharedSecret(bob.PrivateKey, alice.PublicKey)
	if err != nil {
		t.Fatalf("bob derive: %v", err)
	}
	if !bytes.Equal(aliceSecret, bobSecret) {
		t.Error("both sides must derive the same shared secret")
	}
	if len(aliceSecret) != 32 {
		t.Errorf("shared secret must be 32 bytes, got %d", len(aliceSecret))
	}
}

func TestSessionRoundtrip(t *testing.T) {
	a, _ := GenerateKeypair()
	b, _ := GenerateKeypair()
	secret, _ := deriveSharedSecret(a.PrivateKey, b.PublicKey)
	session, err := SessionFromKey(secret)
	if err != nil {
		t.Fatalf("SessionFromKey: %v", err)
	}

	plaintext := []byte("hello")
	ciphertext, err := session.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Equal(ciphertext[:12], make([]byte, 12)) {
		t.Error("nonce should not be all zeros")
	}
	out, err := session.Decrypt(ciphertext, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Error("roundtrip did not preserve plaintext")
	}
}

func TestSessionUniqueNonces(t *testing.T) {
	secret, _ := deriveSharedSecret(must(GenerateKeypair()).PrivateKey, must(GenerateKeypair()).PublicKey)
	session, _ := SessionFromKey(secret)
	c1, _ := session.Encrypt([]byte("x"), nil)
	c2, _ := session.Encrypt([]byte("x"), nil)
	if bytes.Equal(c1[:12], c2[:12]) {
		t.Error("successive encrypts must use unique nonces")
	}
}

func TestSessionAADBinding(t *testing.T) {
	secret, _ := deriveSharedSecret(must(GenerateKeypair()).PrivateKey, must(GenerateKeypair()).PublicKey)
	session, _ := SessionFromKey(secret)
	ciphertext, _ := session.Encrypt([]byte("x"), []byte("aad-a"))
	if _, err := session.Decrypt(ciphertext, []byte("aad-b")); err == nil {
		t.Error("decryption must fail with a different AAD")
	}
}

func TestSessionTamperedCiphertext(t *testing.T) {
	secret, _ := deriveSharedSecret(must(GenerateKeypair()).PrivateKey, must(GenerateKeypair()).PublicKey)
	session, _ := SessionFromKey(secret)
	ciphertext, _ := session.Encrypt([]byte("x"), nil)
	ciphertext[len(ciphertext)-1] ^= 1
	if _, err := session.Decrypt(ciphertext, nil); err == nil {
		t.Error("decryption must fail on tampered ciphertext")
	}
}

func TestSessionEmptyPlaintext(t *testing.T) {
	secret, _ := deriveSharedSecret(must(GenerateKeypair()).PrivateKey, must(GenerateKeypair()).PublicKey)
	session, _ := SessionFromKey(secret)
	ciphertext, err := session.Encrypt(nil, nil)
	if err != nil {
		t.Fatalf("encrypt empty: %v", err)
	}
	out, err := session.Decrypt(ciphertext, nil)
	if err != nil {
		t.Fatalf("decrypt empty: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("empty roundtrip should yield empty, got %d bytes", len(out))
	}
}

func TestComputeAAD(t *testing.T) {
	a := computeAAD("type", "from", "to")
	b := computeAAD("type", "from", "to")
	c := computeAAD("type", "from", "TO")
	if !bytes.Equal(a, b) {
		t.Error("AAD should be deterministic for equal inputs")
	}
	if bytes.Equal(a, c) {
		t.Error("AAD should differ when any component differs")
	}
	if len(a) != 32 {
		t.Errorf("AAD should be 32 bytes (SHA256), got %d", len(a))
	}
}

// Helper: Fatal-free keypair generation for tests where failure is unexpected
func must(kp *Keypair, err error) *Keypair {
	if err != nil {
		panic(err)
	}
	return kp
}
