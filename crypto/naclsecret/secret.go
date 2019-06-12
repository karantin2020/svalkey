// Package naclsecret provides message security using the NaCl secretbox
// ciphers.
package naclsecret

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	// KeySize is the size of a NaCl secret key.
	KeySize = 32

	// NonceSize is the size of a NaCl nonce.
	NonceSize = 24
)

// NaClBox implements Crypter interface for NaCl secret key
type NaClBox struct {
	key *[KeySize]byte
}

// New returns new NaClBox
func New() (*NaClBox, error) {
	n := NaClBox{}
	var err error
	n.key, err = GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("NaclBox was not created, " + err.Error())
	}
	return &n, nil
}

// MarshalJSON converts the NaClBox to JSON.
func (n *NaClBox) MarshalJSON() ([]byte, error) {
	return []byte(hex.EncodeToString(n.key[:])), nil
}

// UnmarshalJSON fills the key m with data from the JSON representation.
func (n *NaClBox) UnmarshalJSON(data []byte) error {
	s, err := hex.DecodeString(string(data))
	if err != nil {
		return err
	}
	n.key = new([KeySize]byte)
	copy((*n.key)[:], s)

	return nil
}

// GenerateKey creates a new random secret key.
func GenerateKey() (*[KeySize]byte, error) {
	key := new([KeySize]byte)
	n, err := rand.Read(key[:])
	if n != KeySize || err != nil {
		return nil, fmt.Errorf("Unable to read enough random bytes for encryption key")
	}

	return key, nil
}

// GenerateNonce creates a new random nonce.
func GenerateNonce() (*[NonceSize]byte, error) {
	nonce := new([NonceSize]byte)
	n, err := rand.Read(nonce[:])
	if n != NonceSize || err != nil {
		return nil, fmt.Errorf("Unable to read enough random bytes for nonce")
	}

	return nonce, nil
}

var (
	// ErrEncrypt is returned when encryption fails.
	ErrEncrypt = errors.New("secret: encryption failed")

	// ErrDecrypt is returned when decryption fails.
	ErrDecrypt = errors.New("secret: decryption failed")
)

// Encrypt generates a random nonce and encrypts the input using
// NaCl's secretbox package. The nonce is prepended to the ciphertext.
// A sealed message will the same size as the original message plus
// secretbox.Overhead bytes long.
func (n *NaClBox) Encrypt(msg []byte) ([]byte, error) {
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, ErrEncrypt
	}

	out := make([]byte, len(nonce))
	copy(out, nonce[:])
	out = secretbox.Seal(out, msg, nonce, n.key)
	return out, nil
}

// Decrypt extracts the nonce from the ciphertext, and attempts to
// decrypt with NaCl's secretbox.
func (n *NaClBox) Decrypt(msg []byte) ([]byte, error) {
	if len(msg) < (NonceSize + secretbox.Overhead) {
		return nil, ErrDecrypt
	}

	var nonce [NonceSize]byte
	copy(nonce[:], msg[:NonceSize])
	out, ok := secretbox.Open(nil, msg[NonceSize:], &nonce, n.key)
	if !ok {
		return nil, ErrDecrypt
	}

	return out, nil
}
