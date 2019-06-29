package poly1305

import (
	"encoding/json"
	"fmt"

	"github.com/karantin2020/svalkey/types"
)

var (
	_ types.Crypter = &Poly1305{}
)

var (
	// ErrEmptyPointer describes empty pointer error
	ErrEmptyPointer = fmt.Errorf("Empty pointer to Poly1305 struct")
)

// Poly1305 is poly1305 implementation of svalkey
// Crypter interface
type Poly1305 struct {
	key *Key
}

// New creates new Poly1305 instance
func New() (*Poly1305, error) {
	key, err := NewRandomKey()
	if err != nil {
		return nil, err
	}
	return &Poly1305{
		key: key,
	}, nil
}

// Decrypt decrypts in, returns decrypted byte slice and error
func (p *Poly1305) Decrypt(in []byte) ([]byte, error) {
	if p == nil {
		return nil, ErrEmptyPointer
	}
	nonce, ciphertext := in[:p.key.NonceSize()], in[p.key.NonceSize():]
	plaintext, err := p.key.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return append([]byte{}, plaintext...), nil
}

// Encrypt encrypts in, returns encrypted byte slice
func (p *Poly1305) Encrypt(in []byte) ([]byte, error) {
	if p == nil {
		return nil, ErrEmptyPointer
	}
	buf := make([]byte, 0, len(in)+Extension+p.key.NonceSize())
	nonce, err := NewRandomNonce()
	if err != nil {
		return nil, err
	}
	ciphertext := p.key.Seal(buf[:0], nonce, in, nil)
	nk := append(append([]byte{}, nonce...), ciphertext...)
	return nk, nil
}

// NonceSize returns AES GCM nonce size
func (p *Poly1305) NonceSize() int {
	return NonceSize()
}

// MarshalJSON converts the AESGCM to JSON.
func (p *Poly1305) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.key)
}

// UnmarshalJSON fills the key m with data from the JSON representation.
func (p *Poly1305) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &p.key)
}
