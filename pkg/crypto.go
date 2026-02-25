package pkg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// CryptoEngine provides authenticated encryption
// Thread-safe: uses atomic nonce counter to prevent nonce reuse
type CryptoEngine struct {
	aead         cipher.AEAD
	method       string
	nonceCounter uint64 // atomic counter for nonce generation
	noncePrefix  []byte // random prefix unique per engine instance
	mu           sync.Mutex
}

// NewCryptoEngine creates a new encryption engine
func NewCryptoEngine(method, secretKey string) (*CryptoEngine, error) {
	// Use HKDF to derive cryptographic key from password
	// Different info strings produce different keys for same password
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		// Fallback to deterministic salt (both sides must match)
		salt = deriveStaticSalt(secretKey)
	}
	// For the tunnel, we need deterministic key derivation
	// Both sides must produce the same key from the same secret
	salt = deriveStaticSalt(secretKey)

	info := []byte("HesarTunnel-v2-encryption")
	hkdfReader := hkdf.New(sha256.New, []byte(secretKey), salt, info)

	var aead cipher.AEAD

	switch method {
	case "chacha20-poly1305":
		key := make([]byte, chacha20poly1305.KeySize)
		if _, err := io.ReadFull(hkdfReader, key); err != nil {
			return nil, fmt.Errorf("HKDF key derivation failed: %w", err)
		}
		var err error
		aead, err = chacha20poly1305.NewX(key) // XChaCha20-Poly1305 (24-byte nonce)
		if err != nil {
			return nil, fmt.Errorf("XChaCha20-Poly1305 init failed: %w", err)
		}

	case "aes-256-gcm":
		key := make([]byte, 32)
		if _, err := io.ReadFull(hkdfReader, key); err != nil {
			return nil, fmt.Errorf("HKDF key derivation failed: %w", err)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("AES cipher init failed: %w", err)
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("GCM init failed: %w", err)
		}

	default:
		return nil, fmt.Errorf("unsupported encryption method: '%s'", method)
	}

	// Generate unique prefix for this engine instance
	noncePrefix := make([]byte, 8)
	rand.Read(noncePrefix)

	return &CryptoEngine{
		aead:        aead,
		method:      method,
		noncePrefix: noncePrefix,
	}, nil
}

// deriveStaticSalt creates a deterministic salt from key
// This ensures both sides derive the same encryption key
func deriveStaticSalt(key string) []byte {
	h := sha256.Sum256([]byte("HesarTunnel-salt-v2-" + key))
	return h[:]
}

// Encrypt encrypts plaintext. Thread-safe.
// Output: [nonce][ciphertext+tag]
// Overhead: NonceSize + TagSize (e.g., 24+16=40 for XChaCha20-Poly1305)
func (ce *CryptoEngine) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := ce.generateNonce()

	// Seal appends ciphertext to dst (nonce)
	// Result: nonce + encrypted_data + auth_tag
	ciphertext := ce.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext. Thread-safe.
// Input: [nonce][ciphertext+tag]
func (ce *CryptoEngine) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := ce.aead.NonceSize()
	if len(ciphertext) < nonceSize+ce.aead.Overhead() {
		return nil, fmt.Errorf("ciphertext too short: %d bytes (min %d)", len(ciphertext), nonceSize+ce.aead.Overhead())
	}

	nonce := ciphertext[:nonceSize]
	encrypted := ciphertext[nonceSize:]

	plaintext, err := ce.aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption/authentication failed: %w", err)
	}

	return plaintext, nil
}

// generateNonce creates a unique nonce using counter + random prefix
// This is safer than pure random because it guarantees no reuse
// even with birthday paradox concerns
func (ce *CryptoEngine) generateNonce() []byte {
	nonceSize := ce.aead.NonceSize()
	nonce := make([]byte, nonceSize)

	// Use atomic counter for first 8 bytes
	counter := atomic.AddUint64(&ce.nonceCounter, 1)
	binary.BigEndian.PutUint64(nonce[0:8], counter)

	// Use random prefix for remaining bytes
	// For XChaCha20 (24-byte nonce): 8 counter + 8 prefix + 8 random
	// For AES-GCM (12-byte nonce): 8 counter + 4 from prefix
	if nonceSize > 8 {
		remaining := nonceSize - 8
		prefixLen := len(ce.noncePrefix)
		if prefixLen > remaining {
			prefixLen = remaining
		}
		copy(nonce[8:8+prefixLen], ce.noncePrefix[:prefixLen])

		// Fill any remaining with random bytes
		if 8+prefixLen < nonceSize {
			rand.Read(nonce[8+prefixLen:])
		}
	}

	return nonce
}

// Overhead returns total bytes added by encryption per message
func (ce *CryptoEngine) Overhead() int {
	return ce.aead.NonceSize() + ce.aead.Overhead()
}

// GenerateAuthToken creates HMAC-SHA256 authentication token
func GenerateAuthToken(secretKey string) []byte {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte("HesarTunnel-auth-v2"))
	return mac.Sum(nil)
}

// VerifyAuthToken verifies authentication token (constant-time)
func VerifyAuthToken(token []byte, secretKey string) bool {
	expected := GenerateAuthToken(secretKey)
	return hmac.Equal(token, expected)
}
