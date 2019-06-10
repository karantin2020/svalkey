package svalkey

import (
	"bytes"
	"fmt"
	"reflect"
	"sync"

	"github.com/abronan/valkeyrie/store"

	"github.com/karantin2020/svalkey/crypto/naclbox"
	"github.com/karantin2020/svalkey/crypto/poly1305"
)

// Store holds data to work with backend db
type Store struct {
	Store   store.Store
	codec   Codec
	crypter Crypter
}

var (
	_ Crypter = &poly1305.Poly1305{}
	_ Crypter = &naclbox.NaClBox{}
)

var pool = &sync.Pool{
	New: func() interface{} { return bytes.NewBuffer(nil) },
}

var (
	// ErrorNilStore represents valkeyrie store nil pointer error
	ErrorNilStore = fmt.Errorf("svalkey: in NewCustomStore" +
		" vstore is nil")
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
	codec Codec) (*Store, error) {
	if vstore == nil {
		return nil, ErrorNilStore
	}
	if codec == nil {
		codec = GobCodec{}
	}
	return &Store{
		Store:   vstore,
		codec:   codec,
		crypter: poly1305.New(),
	}, nil
}

// NewJSONStore creates a new Store, using the underlying
// json codec
func NewJSONStore(vstore store.Store) (*Store, error) {
	return NewCustomStore(vstore, JSONCodec{})
}

// NewXMLStore creates a new Store, using the underlying
// xml codec
func NewXMLStore(vstore store.Store) (*Store, error) {
	return NewCustomStore(vstore, XMLCodec{})
}

// NewStore allows you to create a store with
// a gob underlying Encoding
func NewStore(vstore store.Store) (*Store, error) {
	return NewCustomStore(vstore, GobCodec{})
}

// SetCodec sets new Codec to Store
func (s *Store) SetCodec(codec Codec) {
	s.codec = codec
}

// SetCrypter sets new Crypter to Store
func (s *Store) SetCrypter(crypter Crypter) {
	s.crypter = crypter
}

// Put a value at the specified key
func (s *Store) Put(key string, value interface{},
	options *store.WriteOptions) error {
	val, err := s.toBytes(value)
	if err != nil {
		return err
	}
	sval, err := s.crypter.Encrypt(val)
	if err != nil {
		return err
	}
	return s.Store.Put(key, sval, options)
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
	pair.Value, err = s.crypter.Decrypt(pair.Value)
	if err != nil {
		return err
	}
	err = s.unmarshal(pair.Value, value)
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

// // Watch for changes on a key
// func (s *Store) Watch(key string, stopCh <-chan struct{}, options *store.ReadOptions) (<-chan *store.KVPair, error) {
// 	return s.Store.Watch(key, stopCh, options)
// }

// // WatchTree watches for changes on child nodes under
// // a given directory
// func (s *Store) WatchTree(directory string, stopCh <-chan struct{}, options *store.ReadOptions) (<-chan []*store.KVPair, error) {
// 	return s.Store.WatchTree(directory, stopCh, options)
// }

// // NewLock creates a lock for a given key.
// // The returned Locker is not held and must be acquired
// // with `.Lock`. The Value is optional.
// func (s *Store) NewLock(key string, options *store.LockOptions) (store.Locker, error) {
// 	return s.Store.NewLock(key, options)
// }

// List the content of a given prefix
func (s *Store) List(directory string, value interface{},
	options *store.ReadOptions) error {
	lres, err := s.Store.List(directory, options)
	if err != nil {
		return err
	}
	for i := range lres {
		lres[i].Value, err = s.crypter.Decrypt(lres[i].Value)
		if err != nil {
			return err
		}
	}
	v := reflect.ValueOf(value)
	if v.Kind() != reflect.Ptr {
		return ErrorInvalidOutPointer
	}
	// get the value that the pointer v points to.
	slice := v.Elem()
	if slice.Kind() != reflect.Slice {
		return ErrorInvalidOutSlice
	}
	slice.Set(reflect.MakeSlice(slice.Type(), len(lres), len(lres)))

	for i, val := range lres {
		err := s.unmarshal(val.Value, slice.Index(i).Addr().Interface())
		if err != nil {
			return err
		}
	}
	return nil
}

// DeleteTree deletes a range of keys under a given directory
func (s *Store) DeleteTree(directory string) error {
	return s.Store.DeleteTree(directory)
}

// // AtomicPut CAS operation on a single value.
// // Pass previous = nil to create a new key.
// func (s *Store) AtomicPut(key string, value []byte, previous *store.KVPair, options *store.WriteOptions) (bool, *store.KVPair, error) {
// 	sval := s.crypter.Seal(value)
// 	return s.Store.AtomicPut(key, sval, previous, options)
// }

// // AtomicDelete is an atomic delete of a single value
// func (s *Store) AtomicDelete(key string, previous *store.KVPair) (bool, error) {
// 	return s.Store.AtomicDelete(key, previous)
// }

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