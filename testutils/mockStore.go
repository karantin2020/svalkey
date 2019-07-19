package testutils

import (
	"errors"
	"sync"

	"github.com/abronan/valkeyrie/store"
)

var (
	// ErrorNoKey error if no key in db
	ErrorNoKey = errors.New("Key doesn't exist")
)

// Mock is a struct to test store.Store
type Mock struct {
	kv map[string][]byte
	sync.RWMutex
	closed bool
}

// NewMock return initialized Mock pointer
func NewMock() *Mock {
	return &Mock{
		kv: make(map[string][]byte),
	}
}

// Put saves data to db
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

// Exists Verifies if a Key exists in the store
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

// AtomicPut - Atomic CAS operation on a single value.
// Pass previous = nil to create a new key.
func (m *Mock) AtomicPut(key string,
	value []byte, previous *store.KVPair,
	options *store.WriteOptions) (bool, *store.KVPair, error) {
	return false, nil, nil
}

// AtomicDelete - Atomic delete of a single value
func (m *Mock) AtomicDelete(key string,
	previous *store.KVPair) (bool, error) {
	return false, nil
}

// Close the store connection
func (m *Mock) Close() {
	m.closed = true
}
