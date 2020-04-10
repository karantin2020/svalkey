package svalkey

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"math/rand"

	fuzz "github.com/google/gofuzz"

	"github.com/abronan/valkeyrie"
	"github.com/abronan/valkeyrie/store"
	"github.com/abronan/valkeyrie/store/boltdb"

	"github.com/stretchr/testify/assert"

	"github.com/karantin2020/svalkey/types"
)

var (
	testKey                 = "test key"
	testVal                 = TestType{}
	testSecret              = [32]byte{}
	ErrorNoKey              = errors.New("Key doesn't exist")
	_           store.Store = &Mock{}
	testCrypter types.Crypter
)

const (
	testCount         = 10000
	testListLen       = 100
	testCountBytesMin = 3
	testCountBytesMax = 10000
)

type TestType struct {
	A int64   `gob:"a" json:"a"`
	B int64   `gob:"b" json:"b"`
	C string  `gob:"c" json:"c"`
	D float64 `gob:"d" json:"d"`
	E []byte  `gob:"e" json:"e"`
}

type KeyType struct {
	K string
}

func fuzzString(i *string, c fuzz.Continue) {
	*i = c.RandString()
	for len(*i) < 6 {
		*i = c.RandString()
	}
	// *i = base64.RawURLEncoding.EncodeToString([]byte(*i))
}

func fuzzTestDataKeys(i *KeyType, c fuzz.Continue) {
	i.K = c.RandString()
	for len(i.K) < 6 {
		i.K = c.RandString()
	}
	i.K = base64.RawURLEncoding.EncodeToString([]byte(i.K))
}

var (
	fb = fuzz.NewWithSeed(time.Now().Unix()).NilChance(0).NumElements(testCountBytesMin, testCountBytesMax)
	fm = fuzz.NewWithSeed(time.Now().Unix()).NilChance(0).NumElements(testCount, testCount).Funcs(
		fuzzTestDataKeys,
		fuzzString,
		func(i *[]byte, c fuzz.Continue) {
			fb.Fuzz(i)
		},
	)
)

func newMockStore(t *testing.T) store.Store {
	m := NewMock()
	return m
}

func TestNewCustomStore(t *testing.T) {
	m := newMockStore(t)
	// newTestCrypter(t)
	fs := fuzz.NewWithSeed(time.Now().Unix()).NilChance(0).NumElements(32, 32)
	fs.Fuzz(&testSecret)

	st, err := NewCustomStore(m, GobCodec{}, []byte{1, 0}, testSecret)
	assert.Nil(t, err, "Err in NewCustomStore must be nil")
	assert.NotNil(t, st, "New custom store must not be nil")
}

func TestNewStoreReal(t *testing.T) {
	// consul.Register()
	// etcdv3.Register()
	boltdb.Register()
	// m := newMockStore(t)
	fs := fuzz.New().NumElements(32, 32)
	fs.Fuzz(&testSecret)
	tests := []struct {
		name     string
		register func()
		backend  store.Backend
		client   string
		secret   [32]byte
		want     func(assert.TestingT, interface{}, ...interface{}) bool
		wantErr  bool
	}{
		{
			name:     "Boltdb test",
			register: boltdb.Register,
			backend:  store.BOLTDB,
			client:   "./inner/testdata/test.log",
			secret:   testSecret,
			want:     assert.NotNil,
			wantErr:  false,
		},
		// 		{
		// 			name:     "Consul test",
		// 			register: consul.Register,
		// 			backend:  store.CONSUL,
		// 			client:   "127.0.0.1:8500",
		// 			secret:   testSecret,
		// 			want:     assert.NotNil,
		// 			wantErr:  false,
		// 		},
		// 		{
		// 			name:     "Etcdv3 test",
		// 			register: etcdv3.Register,
		// 			backend:  store.ETCDV3,
		// 			client:   "127.0.0.1:8500",
		// 			secret:   testSecret,
		// 			want:     assert.NotNil,
		// 			wantErr:  false,
		// 		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.register()
			kv, err := valkeyrie.NewStore(tt.backend,
				[]string{tt.client},
				&store.Config{
					ConnectionTimeout: 3 * time.Second,
					SyncPeriod:        30 * time.Second,
					Bucket:            "testBucket",
					PersistConnection: true,
				})
			assert.NoError(t, err, "valkeyrie.NewStore must not return error")
			assert.NotNil(t, kv, "valkeyrie.Store must not be nil")

			st, err := NewStore(kv, []byte{1, 0}, testSecret)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewStore() error = %v, wantErr %v", err, tt.wantErr)
				tt.want(t, st, "New store result must not be nil")
				return
			}
			if tt.backend == store.BOLTDB {
				os.RemoveAll("./inner/testdata")
			}
		})
	}
}

func TestStore_PutAndGet(t *testing.T) {
	m := newMockStore(t)

	st, err := NewCustomStore(m, JSONCodec{}, []byte{0, 1}, testSecret)
	Register(TestType{})
	assert.Nil(t, err, "Err in Put must be nil")
	assert.NotNil(t, st, "New custom store must not be nil")

	testData := map[KeyType]TestType{}
	// fb := fuzz.New().NilChance(0).NumElements(testCountBytesMin, testCountBytesMax)
	// fm := fuzz.New().NilChance(0).NumElements(testCount, testCount).Funcs(
	// 	fuzzString,
	// 	func(i *[]byte, c fuzz.Continue) {
	// 		fb.Fuzz(i)
	// 	},
	// )
	fm.Fuzz(&testData)
	assert.Greater(t, len(testData), testCount/2,
		"Must have greater than testCount/2 random test values")
	i := 0
	for k, v := range testData {
		err = st.Put(k.K, v, nil)
		assert.Nil(t, err, "Err in Put must be nil; key: '"+k.K+"'")
		if i == 3 {
			testKey = k.K
			testVal = v
		}
		i++
	}

	testValErr := TestType{}
	ms := st.Store.(*Mock)
	mv := ms.kv[testKey]
	err = st.unmarshal(mv, &testValErr)
	assert.NotNil(t, err, "Err in Get negative must not be nil")
	assert.NotNil(t, testValErr, "Get negativevalue must not be nil")
	assert.NotEqual(t, testVal, testValErr, "Result Put->Get Value "+
		"in negative must not be equal")

	ic := 0
	for k, v := range testData {
		testValOut := TestType{}
		err = st.Get(k.K, &testValOut, nil)
		if !assert.Nil(t, err, "Err in Get must be nil") {
			fmt.Printf("Error encoded value is: %x\n", ms.kv[k.K])
			fmt.Printf("Error key is: %s\n", k)
			fmt.Printf("Error value is: %v\n", v)
		}
		assert.NotNil(t, testValOut, "Get value must not be nil")
		if !assert.EqualValues(t, v, testValOut, "Result Put->Get Value must be equal") {
			fmt.Printf("error in #%d\n", ic)
			fmt.Printf("Not equal key is: %s\n", k)
			fmt.Printf("Not equal value is: %v\n", v)
			fmt.Printf("Not equal out value is: %v\n", testValOut)
		}
		ic++
	}
	st.Store.DeleteTree("")
}

func TestStore_PutAndGetOne(t *testing.T) {
	m := newMockStore(t)

	st, err := NewCustomStore(m, JSONCodec{}, []byte{0, 1}, testSecret)
	assert.Nil(t, err, "Err in Put must be nil")
	assert.NotNil(t, st, "New custom store must not be nil")

	k := "testKey"
	v := []byte("super secret test value")
	err = st.Put(k, v, nil)
	assert.Nil(t, err, "Err in Put must be nil")

	// ms := st.Store.(*Mock)
	// mv := ms.kv[k]
	// _ = mv
	// fmt.Printf("for key '%v' AES-GCM-256 encoded value is '%v'\n", testKey, mv)
	testValOut := []byte{}
	err = st.Get(k, &testValOut, nil)
	assert.Nil(t, err, "Err in Get must be nil")
	// fmt.Printf("for key '%v' AES-GCM-256 decoded value is '%s'\n", testKey, string(testValOut))

	ct, err := NewCustomStore(m, JSONCodec{}, []byte{1, 0}, testSecret)
	assert.Nil(t, err, "Err in Put must be nil")
	assert.NotNil(t, st, "New custom store must not be nil")

	testValOut = testValOut[:0]
	err = ct.Get(k, &testValOut, nil)
	assert.Nil(t, err, "Err in Get must be nil")
	// fmt.Printf("for key '%v' decoded value is '%s'\n", testKey, string(testValOut))

	// Negative password test
	fs := fuzz.NewWithSeed(time.Now().Unix()).NilChance(0).NumElements(32, 32)
	fs.Fuzz(&testSecret)
	fs.Fuzz(&testSecret)
	nt, err := NewCustomStore(m, JSONCodec{}, []byte{1, 0}, testSecret)
	assert.Nil(t, err, "Err in Put must be nil")
	assert.NotNil(t, nt, "New custom store must not be nil")

	testValOut = testValOut[:0]
	err = nt.Get(k, &testValOut, nil)
	assert.NotNil(t, err, "Err in Get must not be nil: incorrect db password")
	// fmt.Printf("Get operation returned error: %v\n", err)
}

func TestStore_List(t *testing.T) {
	m := newMockStore(t)

	st, err := NewCustomStore(m, JSONCodec{}, []byte{1, 0}, testSecret)
	Register(TestType{})
	assert.Nil(t, err, "Err in Put must be nil")
	assert.NotNil(t, st, "New custom store must not be nil")

	testData := map[KeyType]TestType{}
	// fm := fuzz.New().NilChance(0).NumElements(testCount, testCount).Funcs(
	// 	fuzzString,
	// )
	fm.Fuzz(&testData)
	for k, v := range testData {
		err = st.Put(k.K, v, nil)
		assert.Nil(t, err, "Err in Put must be nil")
	}

	testType := []TestType{}
	retList, err := st.List(testKey, &testType, nil)
	assert.Nil(t, err, "Err in List must be nil")
	assert.NotNil(t, testType, "List value must not be nil")
	assert.NotNil(t, retList, "List return []ListPair must not be nil")
	assert.EqualValues(t, len(testData), len(retList),
		"In List returned slices length must be equal to length of"+
			" original test data")
	for _, v := range retList {
		assert.EqualValues(t, testData[KeyType{v.key}], v.value.(TestType))
	}
	m.DeleteTree("")
}

type int63nPicker interface {
	Int63n(int64) int64
}

type charRange struct {
	first, last rune
}

// choose returns a random unicode character from the given range, using the
// given randomness source.
func (cr charRange) choose(r int63nPicker) rune {
	count := int64(cr.last - cr.first + 1)
	return cr.first + rune(r.Int63n(count))
}

var unicodeRanges = []charRange{
	{' ', '~'}, // ASCII characters
	// {'\u00a0', '\u02af'}, // Multi-byte encoded characters
	// {'\u4e00', '\u9fff'}, // Common CJK (even longer encodings)
}

// randString makes a random string up to 20 characters long. The returned string
// may include a variety of (valid) UTF-8 encodings.
func randString(r *rand.Rand) string {
	n := r.Intn(20)
	runes := make([]rune, n)
	for i := range runes {
		runes[i] = unicodeRanges[r.Intn(len(unicodeRanges))].choose(r)
	}
	return string(runes)
}

// randUint64 makes random 64 bit numbers.
// Weirdly, rand doesn't have a function that gives you 64 random bits.
func randUint64(r *rand.Rand) uint64 {
	return uint64(r.Uint32())<<32 | uint64(r.Uint32())
}
