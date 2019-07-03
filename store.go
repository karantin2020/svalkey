package svalkey

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"reflect"
	"sync"

	"github.com/abronan/valkeyrie/store"
	"github.com/karantin2020/svalkey/types"
	"github.com/minio/sio"
	"golang.org/x/crypto/hkdf"
)

// Store holds data to work with backend db
type Store struct {
	Store        store.Store
	codec        types.Codec
	key          [32]byte
	cipherSuites []byte
}

// ListPair holds return of List store method
type ListPair struct {
	key   string
	value interface{}
}

var pool = &sync.Pool{
	New: func() interface{} { return bytes.NewBuffer(nil) },
}

var (
	// ErrorNilStore represents valkeyrie store nil pointer error
	ErrorNilStore = fmt.Errorf("svalkey: in NewCustomStore" +
		" vstore is nil")
	// ErrCipherSuites represents valkeyrie store nil or empty cipherSuites error
	ErrCipherSuites = fmt.Errorf("svalkey: in NewCustomStore" +
		" cipherSuites is nill or empty")
	// ErrorInvalidUnmarshal represents invalid unmarshal value error
	ErrorInvalidUnmarshal = fmt.Errorf("svalkey: in Get" +
		" unmarshal value is not pointer type")
	// ErrorNilValue  represents nil unmarshal value error
	ErrorNilValue = fmt.Errorf("svalkey: in Get" +
		" unmarshal value is not pointer type")
	// ErrorInvalidOutPointer represents invalid out var type error
	ErrorInvalidOutPointer = fmt.Errorf("svalkey: in List" +
		" unmarshal value is not pointer type")
	// ErrorInvalidOutSlice represents invalid out var type error
	ErrorInvalidOutSlice = fmt.Errorf("svalkey: in List" +
		" unmarshal value is not pointer to slice type")
)

// NewCustomStore creates new *Store with custom underlying codec
func NewCustomStore(vstore store.Store,
	codec types.Codec, cipherSuites []byte, key [32]byte) (*Store, error) {
	if vstore == nil {
		return nil, ErrorNilStore
	}
	if codec == nil {
		codec = GobCodec{}
	}
	if cipherSuites == nil || len(cipherSuites) == 0 {
		return nil, ErrCipherSuites
	}
	return &Store{
		Store:        vstore,
		codec:        codec,
		cipherSuites: cipherSuites,
	}, nil
}

// NewJSONStore creates a new Store, using the underlying
// json codec
func NewJSONStore(vstore store.Store,
	cipherSuites []byte, key [32]byte) (*Store, error) {
	return NewCustomStore(vstore, JSONCodec{},
		cipherSuites, key)
}

// NewXMLStore creates a new Store, using the underlying
// xml codec
func NewXMLStore(vstore store.Store,
	cipherSuites []byte, key [32]byte) (*Store, error) {
	return NewCustomStore(vstore, XMLCodec{},
		cipherSuites, key)
}

// NewStore allows you to create a store with
// a gob underlying Encoding
func NewStore(vstore store.Store,
	cipherSuites []byte, key [32]byte) (*Store, error) {
	return NewCustomStore(vstore, GobCodec{},
		cipherSuites, key)
}

// Close closes Store.Store connection, frees resources
func (s *Store) Close() {
	s.Store.Close()
	for i := range s.key {
		s.key[i] = 0
	}
}

// SetCodec sets new Codec to Store
func (s *Store) SetCodec(codec types.Codec) {
	s.codec = codec
}

// SetCipherSuites sets new Crypter to Store
func (s *Store) SetCipherSuites(cipherSuites []byte) {
	s.cipherSuites = cipherSuites
}

// Put a value at the specified key
func (s *Store) Put(key string, value interface{},
	options *store.WriteOptions) error {
	val, err := s.encode(value, s.cipherSuites, s.key[:])
	if err != nil {
		return err
	}
	return s.Store.Put(key, val, options)
}

// Get a value given its key
func (s *Store) Get(key string, value interface{},
	options *store.ReadOptions) error {
	if value == nil {
		return ErrorNilValue
	}
	rv := reflect.ValueOf(value)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return ErrorInvalidUnmarshal
	}
	pair, err := s.Store.Get(key, options)
	if err != nil {
		return err
	}
	// pair.Value, err = s.crypter.Decrypt(pair.Value)
	// if err != nil {
	// 	return err
	// }
	err = s.decode(pair.Value, value, s.cipherSuites, s.key[:])
	if err != nil {
		return err
	}
	return nil
}

// Delete the value at the specified key
func (s *Store) Delete(key string) error {
	return s.Store.Delete(key)
}

// Exists verifies if a Key exists in the store
func (s *Store) Exists(key string, options *store.ReadOptions) (bool, error) {
	return s.Store.Exists(key, options)
}

// List the content of a given prefix
func (s *Store) List(directory string, value interface{},
	options *store.ReadOptions) ([]*ListPair, error) {
	lres, err := s.Store.List(directory, options)
	if err != nil {
		return nil, err
	}
	retList := []*ListPair{}
	v := reflect.ValueOf(value)
	if v.Kind() != reflect.Ptr {
		return nil, ErrorInvalidOutPointer
	}
	// get the value that the pointer v points to.
	slice := v.Elem()
	if slice.Kind() != reflect.Slice {
		return nil, ErrorInvalidOutSlice
	}
	slice.Set(reflect.MakeSlice(slice.Type(), len(lres), len(lres)))

	for i, val := range lres {
		err := s.decode(val.Value,
			slice.Index(i).Addr().Interface(),
			s.cipherSuites,
			s.key[:])
		if err != nil {
			return nil, err
		}
		retList = append(retList, &ListPair{val.Key, slice.Index(i).Interface()})
	}
	return retList, nil
}

// DeleteTree deletes a range of keys under a given directory
func (s *Store) DeleteTree(directory string) error {
	return s.Store.DeleteTree(directory)
}

func deriveKey(masterkey []byte) ([]byte, []byte, error) {
	var nonce [32]byte
	if n, err := io.ReadFull(rand.Reader, nonce[:]); err != nil || n != 32 {
		return nil, nil, fmt.Errorf("svalkey: error key derivation, no nonce was got")
	}

	// derive an encryption key from the master key and the nonce
	var key [32]byte
	kdf := hkdf.New(sha256.New, masterkey, nonce[:], nil)
	if n, err := io.ReadFull(kdf, key[:]); err != nil || n != 32 {
		return nil, nil, fmt.Errorf("svalkey: error key derivation, no key was derived")
	}
	return key[:], nonce[:], nil
}

func (s *Store) encode(val interface{}, cs []byte, key []byte) (data []byte, err error) {
	buf := pool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		pool.Put(buf)
	}()
	dkey, nonce, err := deriveKey(key)
	if err != nil {
		return nil, err
	}
	n, err := buf.Write(nonce)
	if err != nil || n != 32 {
		return nil, fmt.Errorf("svalkey: error prefix nonce in value; %s", err.Error())
	}
	encrypted, err := sio.EncryptWriter(buf, sio.Config{Key: dkey})
	if err != nil {
		return nil, fmt.Errorf("svalkey: failed to make encrypt writer; %s", err.Error())
	}
	enc := s.codec.NewEncoder(encrypted)
	if pCodec, ok := s.codec.(*pooledCodec); ok && err == nil {
		defer pCodec.PutEncoder(enc)
	}
	err = enc.Encode(val)
	if err != nil {
		return nil, fmt.Errorf("svalkey: error value encode; %s", err.Error())
	}
	encrypted.Close()
	data = append(data, buf.Bytes()...)

	return data, err
}

func (s *Store) decode(data []byte, val interface{}, cs []byte, key []byte) (err error) {
	buf := bytes.NewReader(data)
	var nonce [32]byte
	n, err := buf.Read(nonce[:])
	if err != nil || n != 32 {
		return fmt.Errorf("svalkey: error read nonce from db value")
	}
	var dkey [32]byte
	kdf := hkdf.New(sha256.New, key, nonce[:], nil)
	if n, err := io.ReadFull(kdf, dkey[:]); err != nil || n != 32 {
		return fmt.Errorf("svalkey: error key derivation, no key was derived")
	}
	decrypted, err := sio.DecryptReader(buf, sio.Config{Key: dkey[:]})
	if err != nil {
		return fmt.Errorf("svalkey: error decode value; %s", err.Error())
	}
	dec := s.codec.NewDecoder(decrypted)
	if pCodec, ok := s.codec.(*pooledCodec); ok && err == nil {
		defer pCodec.PutDecoder(dec)
	}
	err = dec.Decode(val)
	if err != nil {
		return fmt.Errorf("svalkey: error decode key; %s", err.Error())
	}
	return err
}

func (s *Store) toBytes(key interface{}) (keyBytes []byte, err error) {
	switch k := key.(type) {
	case string:
		return []byte(k), nil
	case []byte:
		return k, nil
	default:
		return s.marshal(key)
	}
}

func (s *Store) marshal(val interface{}) (data []byte, err error) {
	buf := pool.Get().(*bytes.Buffer)
	enc := s.codec.NewEncoder(buf)
	err = enc.Encode(val)
	data = append(data, buf.Bytes()...)
	buf.Reset()
	pool.Put(buf)

	if pCodec, ok := s.codec.(*pooledCodec); ok && err == nil {
		pCodec.PutEncoder(enc)
	}

	return data, err
}

func (s *Store) unmarshal(data []byte, val interface{}) (err error) {
	dec := s.codec.NewDecoder(bytes.NewReader(data))
	err = dec.Decode(val)

	if pCodec, ok := s.codec.(*pooledCodec); ok && err == nil {
		pCodec.PutDecoder(dec)
	}
	return err
}
