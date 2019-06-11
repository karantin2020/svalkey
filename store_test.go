package svalkey

import (
	"errors"
	"strconv"
	"sync"
	"testing"

	"github.com/abronan/valkeyrie/store"
	"github.com/stretchr/testify/assert"

	"github.com/karantin2020/svalkey/crypto/naclbox"
)

var (
	testKey                = "test key"
	testVal                = []byte("test val")
	ErrorNoKey             = errors.New("Key doesn't exist")
	_          store.Store = &Mock{}
)

type TestType struct {
	A, B int
}

func newMockStore(t *testing.T) store.Store {
	m := NewMock()
	return m
}

func TestNewCustomStore(t *testing.T) {
	m := newMockStore(t)

	st, err := NewCustomStore(m, GobCodec{})
	assert.Nil(t, err, "Err in NewCustomStore must be nil")
	assert.NotNil(t, st, "New custom store must not be nil")
}

func TestStore_PutAndGet(t *testing.T) {
	m := newMockStore(t)

	st, err := NewCustomStore(m, GobCodec{})
	Register(TestType{})
	assert.Nil(t, err, "Err in Put must be nil")
	assert.NotNil(t, st, "New custom store must not be nil")

	testValIn := TestType{234, 654}
	err = st.Put(testKey, testValIn, nil)
	assert.Nil(t, err, "Err in Put must be nil")

	testValErr := TestType{}
	ms := st.Store.(*Mock)
	mv := ms.kv[testKey]
	err = st.unmarshal(mv, &testValErr)
	assert.NotNil(t, err, "Err in Get negative must not be nil")
	assert.NotNil(t, testValErr, "Get negativevalue must not be nil")
	assert.NotEqual(t, testValIn, testValErr, "Result Put->Get Value "+
		"in negative must be equal")

	testValOut := TestType{}
	err = st.Get(testKey, &testValOut, nil)
	assert.Nil(t, err, "Err in Get must be nil")
	assert.NotNil(t, testValOut, "Get value must not be nil")
	assert.Equal(t, testValIn, testValOut, "Result Put->Get Value must be equal")
}

type Mock struct {
	kv map[string][]byte
	sync.RWMutex
	closed bool
}

func NewMock() *Mock {
	return &Mock{
		kv: make(map[string][]byte),
	}
}

func (m *Mock) Put(key string,
	value []byte, options *store.WriteOptions) error {
	m.Lock()
	defer m.Unlock()
	m.kv[key] = value
	return nil
}

// Get a value given its key
func (m *Mock) Get(key string,
	options *store.ReadOptions) (*store.KVPair, error) {
	m.RLock()
	defer m.RUnlock()
	if val, ok := m.kv[key]; ok {
		return &store.KVPair{
			Key:       key,
			Value:     val,
			LastIndex: 0,
		}, nil
	}
	return nil, ErrorNoKey
}

// Delete the value at the specified key
func (m *Mock) Delete(key string) error {
	m.Lock()
	defer m.Unlock()
	delete(m.kv, key)
	return nil
}

// Verify if a Key exists in the store
func (m *Mock) Exists(key string,
	options *store.ReadOptions) (bool, error) {
	m.RLock()
	defer m.RUnlock()
	if _, ok := m.kv[key]; ok {
		return true, nil
	}
	return false, nil
}

// Watch for changes on a key
func (m *Mock) Watch(key string,
	stopCh <-chan struct{}, options *store.ReadOptions) (<-chan *store.KVPair, error) {
	return nil, nil
}

// WatchTree watches for changes on child nodes under
// a given directory
func (m *Mock) WatchTree(directory string,
	stopCh <-chan struct{}, options *store.ReadOptions) (<-chan []*store.KVPair, error) {
	return nil, nil
}

// NewLock creates a lock for a given key.
// The returned Locker is not held and must be acquired
// with `.Lock`. The Value is optional.
func (m *Mock) NewLock(key string,
	options *store.LockOptions) (store.Locker, error) {
	return nil, nil
}

// List the content of a given prefix
func (m *Mock) List(directory string,
	options *store.ReadOptions) ([]*store.KVPair, error) {
	m.RLock()
	defer m.RUnlock()
	ret := []*store.KVPair{}
	for k, v := range m.kv {
		ret = append(ret, &store.KVPair{
			Key:       k,
			Value:     v,
			LastIndex: 0,
		})
	}
	return ret, nil
}

// DeleteTree deletes a range of keys under a given directory
func (m *Mock) DeleteTree(directory string) error {
	m.Lock()
	defer m.Unlock()
	m.kv = make(map[string][]byte)
	return nil
}

// Atomic CAS operation on a single value.
// Pass previous = nil to create a new key.
func (m *Mock) AtomicPut(key string,
	value []byte, previous *store.KVPair,
	options *store.WriteOptions) (bool, *store.KVPair, error) {
	return false, nil, nil
}

// Atomic delete of a single value
func (m *Mock) AtomicDelete(key string,
	previous *store.KVPair) (bool, error) {
	return false, nil
}

// Close the store connection
func (m *Mock) Close() {
	m.closed = true
}

func TestStore_List(t *testing.T) {
	m := newMockStore(t)

	st, err := NewCustomStore(m, GobCodec{})
	nc, err := naclbox.New()
	assert.Nil(t, err, "Err in New nacl key must be nil")
	assert.NotNil(t, nc, "New nacl key must not be nil")
	st.SetCrypter(nc)
	Register(TestType{})
	assert.Nil(t, err, "Err in Put must be nil")
	assert.NotNil(t, st, "New custom store must not be nil")

	testValIn := []TestType{{234, 654}, {456, 876}}
	for i := range testValIn {
		err = st.Put(testKey+strconv.Itoa(i), testValIn[i], nil)
		assert.Nil(t, err, "Err in Put must be nil")
	}

	testValOut := []TestType{}
	err = st.List(testKey, &testValOut, nil)
	assert.Nil(t, err, "Err in List must be nil")
	assert.NotNil(t, testValOut, "List value must not be nil")
	sum1 := 0
	for _, v := range testValIn {
		sum1 += v.A + v.B
	}
	sum2 := 0
	for _, v := range testValOut {
		sum2 += v.A + v.B
	}
	assert.Equal(t, sum1, sum2, "Result Put...->List Value must be equal")
}
