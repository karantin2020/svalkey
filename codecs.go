package svalkey

import (
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"io"

	"github.com/karantin2020/svalkey/types"
)

var (
	_ types.Codec = XMLCodec{}
	_ types.Codec = JSONCodec{}
	_ types.Codec = GobCodec{}
)

// XMLCodec is used to encode/decode XML
type XMLCodec struct{}

// NewEncoder returns a new xml encoder which writes to w
func (c XMLCodec) NewEncoder(w io.Writer) types.Encoder {
	return xml.NewEncoder(w)
}

// NewDecoder returns a new xml decoder which reads from r
func (c XMLCodec) NewDecoder(r io.Reader) types.Decoder {
	return xml.NewDecoder(r)
}

// JSONCodec is used to encode/decode JSON
type JSONCodec struct{}

// NewEncoder returns a new json encoder which writes to w
func (c JSONCodec) NewEncoder(w io.Writer) types.Encoder {
	return json.NewEncoder(w)
}

// NewDecoder returns a new json decoder which reads from r
func (c JSONCodec) NewDecoder(r io.Reader) types.Decoder {
	return json.NewDecoder(r)
}

// GobCodec is used to encode/decode using the Gob format.
type GobCodec struct{}

// Register registers the type using gob.Register for use
// with GobCodec.
func Register(value interface{}) {
	gob.Register(value)
}

// RegisterName registers the type using gob.RegisterName
// for use with GobCodec.
func RegisterName(name string, value interface{}) {
	gob.RegisterName(name, value)
}

// NewEncoder returns a new gob encoder which writes to w
func (c GobCodec) NewEncoder(w io.Writer) types.Encoder {
	return gob.NewEncoder(w)
}

// NewDecoder returns a new gob decoder which reads from r
func (c GobCodec) NewDecoder(r io.Reader) types.Decoder {
	return gob.NewDecoder(r)
}
