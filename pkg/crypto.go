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
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type CryptoEngine struct {
	aead    cipher.AEAD
	counter uint64
	prefix  []byte
}

func NewCryptoEngine(method, key string) (*CryptoEngine, error) {
	salt := deriveSalt(key)
	info := []byte("HesarTunnel-v2")
	kdf := hkdf.New(sha256.New, []byte(key), salt, info)

	var aead cipher.AEAD
	var err error

	switch method {
	case "chacha20-poly1305":
		k := make([]byte, chacha20poly1305.KeySize)
		if _, err = io.ReadFull(kdf, k); err != nil {
			return nil, fmt.Errorf("key derive: %w", err)
		}
		aead, err = chacha20poly1305.NewX(k)
		if err != nil {
			return nil, fmt.Errorf("chacha20 init: %w", err)
		}

	case "aes-256-gcm":
		k := make([]byte, 32)
		if _, err = io.ReadFull(kdf, k); err != nil {
			return nil, fmt.Errorf("key derive: %w", err)
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, fmt.Errorf("aes init: %w", err)
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("gcm init: %w", err)
		}

	default:
		return nil, fmt.Errorf("unknown method: %s", method)
	}

	prefix := make([]byte, 8)
	rand.Read(prefix)

	return &CryptoEngine{aead: aead, prefix: prefix}, nil
}

func deriveSalt(key string) []byte {
	h := sha256.Sum256([]byte("HesarTunnel-salt-" + key))
	return h[:]
}

func (ce *CryptoEngine) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := ce.makeNonce()
	return ce.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (ce *CryptoEngine) Decrypt(ciphertext []byte) ([]byte, error) {
	ns := ce.aead.NonceSize()
	if len(ciphertext) < ns+ce.aead.Overhead() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return ce.aead.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
}

func (ce *CryptoEngine) makeNonce() []byte {
	nonce := make([]byte, ce.aead.NonceSize())
	c := atomic.AddUint64(&ce.counter, 1)
	binary.BigEndian.PutUint64(nonce[0:8], c)
	copy(nonce[8:], ce.prefix)
	return nonce
}

func (ce *CryptoEngine) Overhead() int {
	return ce.aead.NonceSize() + ce.aead.Overhead()
}

func GenerateAuthToken(key string) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte("HesarTunnel-auth-v2"))
	return mac.Sum(nil)
}

func VerifyAuthToken(token []byte, key string) bool {
	return hmac.Equal(token, GenerateAuthToken(key))
}
