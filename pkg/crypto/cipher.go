package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// CipherSuite provides authenticated encryption using
// XChaCha20-Poly1305 with HKDF key derivation.
// Chosen for: speed on ARM/x86 without AES-NI,
// constant-time operations, 192-bit nonce (no reuse risk).
type CipherSuite struct {
	aead     cipher.AEAD
	nonceCtr atomic.Uint64
}

// DeriveKey uses HKDF-SHA256 to derive encryption key from PSK + salt.
// This ensures unique keys per session even with same PSK.
func DeriveKey(psk []byte, salt []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, psk, salt, []byte("hesartunnel-v1"))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	return key, nil
}

// NewCipherSuite creates an XChaCha20-Poly1305 cipher from derived key.
func NewCipherSuite(key []byte) (*CipherSuite, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("cipher init: %w", err)
	}
	return &CipherSuite{aead: aead}, nil
}

// Encrypt encrypts plaintext with associated data (AD).
// Uses random nonce + counter to guarantee uniqueness.
// Format: [24-byte nonce][ciphertext+tag]
func (cs *CipherSuite) Encrypt(plaintext, ad []byte) ([]byte, error) {
	nonce := make([]byte, cs.aead.NonceSize())

	// First 16 bytes random, last 8 bytes counter
	if _, err := rand.Read(nonce[:16]); err != nil {
		return nil, err
	}
	ctr := cs.nonceCtr.Add(1)
	binary.BigEndian.PutUint64(nonce[16:], ctr)

	ciphertext := cs.aead.Seal(nonce, nonce, plaintext, ad)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext with associated data verification.
func (cs *CipherSuite) Decrypt(ciphertext, ad []byte) ([]byte, error) {
	nonceSize := cs.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	encrypted := ciphertext[nonceSize:]

	plaintext, err := cs.aead.Open(nil, nonce, encrypted, ad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (tampered?): %w", err)
	}
	return plaintext, nil
}

// GenerateSalt creates a random 32-byte salt for key derivation.
// Ensures first byte is not 0x16 to avoid confusion with TLS ClientHello
// during the auto-detection handshake phase.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	// Avoid 0x16 (TLS Handshake) as first byte for protocol disambiguation
	if salt[0] == 0x16 {
		salt[0] ^= 0xFF
	}
	return salt, nil
}

// Overhead returns the total overhead per encrypted frame.
// 24 (nonce) + 16 (Poly1305 tag) = 40 bytes
func (cs *CipherSuite) Overhead() int {
	return cs.aead.NonceSize() + cs.aead.Overhead()
}
