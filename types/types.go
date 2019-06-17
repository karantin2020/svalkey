package types

import (
	"io"
)

// Crypter provides sync crypto encoding mechanism
type Crypter interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
	// MarshalJSON() ([]byte, error)
	// UnmarshalJSON([]byte) error
}

// Codec provides a mechanism for storing/retriving
// objects as streams of data
type Codec interface {
	NewEncoder(io.Writer) Encoder
	NewDecoder(io.Reader) Decoder
}

// Decoder is used to decode objects
type Decoder interface {
	Decode(interface{}) error
}

// Encoder is used to encode objects
type Encoder interface {
	Encode(interface{}) error
}
