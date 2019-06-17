// Package aesgcm contains an example of using AES-(128/256)-GCM
package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/karantin2020/svalkey/crypto"
	"github.com/karantin2020/svalkey/types"
)

var (
	_ types.Crypter = &AESGCM{}
)

const (
	// NonceSize holds nonce length
	NonceSize = 12
)

// AESSize type to represent key length
type AESSize int8

const (
	// AES128 represents AES-128-GCM key length
	AES128 AESSize = 16
	// AES192 represents AES-192-GCM key length
	AES192 AESSize = 24
	// AES256 represents AES-256-GCM key length
	AES256 AESSize = 32
)

var (
	// ErrEncrypt represents encryption error
	ErrEncrypt = errors.New("secret: encryption failed")
	// ErrDecrypt represents decryption error
	ErrDecrypt = errors.New("secret: decryption failed")
)

// AESGCM implements Crypter interface for AES-(128/256)-GCM secret key
type AESGCM struct {
	key    []byte
	key128 [AES128]byte
	key192 [AES192]byte
	key256 [AES256]byte
}

// New returns new AESGCM
func New(s AESSize) (*AESGCM, error) {
	n := AESGCM{}
	var err error
	switch s {
	case AES128:
		n.key, err = GenerateKey(s)
		if err != nil {
			return nil, fmt.Errorf("AESGCM was not created, " + err.Error())
		}
		copy(n.key128[:], n.key)
		n.key = n.key128[:]
	case AES192:
		n.key, err = GenerateKey(s)
		if err != nil {
			return nil, fmt.Errorf("AESGCM was not created, " + err.Error())
		}
		copy(n.key192[:], n.key)
		n.key = n.key192[:]
	case AES256:
		n.key, err = GenerateKey(s)
		if err != nil {
			return nil, fmt.Errorf("AESGCM was not created, " + err.Error())
		}
		copy(n.key256[:], n.key)
		n.key = n.key256[:]
	default:
		return nil, fmt.Errorf("AESGCM was not created: incorrect key length")
	}
	return &n, nil
}

// GenerateKey generates a new AES-256 key.
func GenerateKey(s AESSize) ([]byte, error) {
	return crypto.RandBytes(int(s))
}

// GenerateNonce generates a new AES-GCM nonce.
func GenerateNonce() ([]byte, error) {
	return crypto.RandBytes(NonceSize)
}

// Encrypt secures a message using AES-GCM.
func (g *AESGCM) Encrypt(message []byte) ([]byte, error) {
	c, err := aes.NewCipher(g.key)
	if err != nil {
		return nil, ErrEncrypt
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, ErrEncrypt
	}

	nonce, err := GenerateNonce()
	if err != nil {
		return nil, ErrEncrypt
	}

	// Seal will append the output to the first argument; the usage
	// here appends the ciphertext to the nonce. The final parameter
	// is any additional data to be authenticated.
	out := gcm.Seal(nonce, nonce, message, nil)
	return out, nil
}

// Decrypt recovers a message secured using AES-GCM.
func (g *AESGCM) Decrypt(message []byte) ([]byte, error) {
	if len(message) <= NonceSize {
		return nil, ErrDecrypt
	}

	c, err := aes.NewCipher(g.key)
	if err != nil {
		return nil, ErrDecrypt
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, ErrDecrypt
	}

	nonce := make([]byte, NonceSize)
	copy(nonce, message)

	out, err := gcm.Open(nil, nonce, message[NonceSize:], nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return out, nil
}

// MarshalJSON converts the AESGCM to JSON.
func (g *AESGCM) MarshalJSON() ([]byte, error) {
	return []byte(hex.EncodeToString(g.key[:])), nil
}

// UnmarshalJSON fills the key m with data from the JSON representation.
func (g *AESGCM) UnmarshalJSON(data []byte) error {
	s, err := hex.DecodeString(string(data))
	if err != nil {
		return err
	}
	switch len(s) {
	case 16:
		copy(g.key128[:], s)
		g.key = g.key128[:]
	case 24:
		copy(g.key192[:], s)
		g.key = g.key192[:]
	case 32:
		copy(g.key256[:], s)
		g.key = g.key256[:]
	default:
		return fmt.Errorf("AESGCM was not unmarshalled: incorrect key length")
	}
	return nil
}
