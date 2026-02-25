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
	kdf := hkdf.New(sha256.New, []byte(key), salt, []byte("HesarTunnel-v2"))
	var aead cipher.AEAD
	var err error
	switch method {
	case "chacha20-poly1305":
		k := make([]byte, chacha20poly1305.KeySize)
		if _, err = io.ReadFull(kdf, k); err != nil {
			return nil, err
		}
		aead, err = chacha20poly1305.NewX(k)
	case "aes-256-gcm":
		k := make([]byte, 32)
		if _, err = io.ReadFull(kdf, k); err != nil {
			return nil, err
		}
		var block cipher.Block
		block, err = aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
	default:
		return nil, fmt.Errorf("unknown method: %s", method)
	}
	if err != nil {
		return nil, err
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
	n := copy(nonce[8:], ce.prefix)
	if 8+n < len(nonce) {
		rand.Read(nonce[8+n:])
	}
	return nonce
}

func GenerateAuthToken(key string) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte("HesarTunnel-auth-v2"))
	return mac.Sum(nil)
}

func VerifyAuthToken(token []byte, key string) bool {
	return hmac.Equal(token, GenerateAuthToken(key))
}
