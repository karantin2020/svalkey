package chacha20poly1305

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/karantin2020/svalkey/crypto"

	"github.com/karantin2020/svalkey/types"
	ccp "golang.org/x/crypto/chacha20poly1305"
)

var (
	_ types.Crypter = &XChaCha20Poly1305{}
)

var (
	// ErrEncrypt represents encryption error
	ErrEncrypt = fmt.Errorf("chacha20poly1305: encryption failed")
	// ErrDecrypt represents decryption error
	ErrDecrypt = fmt.Errorf("chacha20poly1305: decryption failed")
)

// XChaCha20Poly1305 implements Crypter interface for XChaCha20-Poly1305 secret key
type XChaCha20Poly1305 struct {
	key  [32]byte
	aead cipher.AEAD
}

// New returns new AESGCM
func New(key []byte) (*XChaCha20Poly1305, error) {
	xkey := XChaCha20Poly1305{}
	if len(key) != 0 && len(key) != ccp.KeySize {
		return nil, fmt.Errorf("Unable to create new secret: incorrect key length")
	}
	if key == nil {
		n, err := rand.Read(xkey.key[:])
		if n != ccp.KeySize || err != nil {
			return nil, fmt.Errorf("Unable to read enough random bytes for encryption key")
		}
	} else {
		copy(xkey.key[:], key)
	}
	var err error
	xkey.aead, err = ccp.NewX(xkey.key[:])
	if err != nil {
		return nil, fmt.Errorf("Unable to create new xchacha20poly1305 key: %s", err.Error())
	}
	return &xkey, nil
}

// Encrypt secures a message using AES-GCM.
func (g *XChaCha20Poly1305) Encrypt(message []byte) ([]byte, error) {
	nonce, err := crypto.RandBytes(ccp.NonceSizeX)
	if err != nil {
		return nil, ErrEncrypt
	}

	out := g.aead.Seal(nonce, nonce, message, nil)
	return out, nil
}

// Decrypt recovers a message secured using AES-GCM.
func (g *XChaCha20Poly1305) Decrypt(message []byte) ([]byte, error) {
	if len(message) <= ccp.NonceSizeX {
		return nil, ErrDecrypt
	}

	nonce := make([]byte, ccp.NonceSizeX)
	copy(nonce, message)

	out, err := g.aead.Open(nil, nonce, message[ccp.NonceSizeX:], nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return out, nil
}

// NonceSize returns AES GCM nonce size
func (g *XChaCha20Poly1305) NonceSize() int {
	return ccp.NonceSizeX
}

// MarshalJSON converts the AESGCM to JSON.
func (g *XChaCha20Poly1305) MarshalJSON() ([]byte, error) {
	return []byte(hex.EncodeToString(g.key[:])), nil
}

// UnmarshalJSON fills the key m with data from the JSON representation.
func (g *XChaCha20Poly1305) UnmarshalJSON(data []byte) error {
	s, err := hex.DecodeString(string(data))
	if err != nil {
		return err
	}
	copy(g.key[:], s)
	g.aead, err = ccp.NewX(g.key[:])
	if err != nil {
		return fmt.Errorf("Unable to create new xchacha20poly1305 key: %s", err.Error())
	}
	return nil
}
