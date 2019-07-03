package svalkey

import (
	"errors"
	"fmt"
	"testing"

	fuzz "github.com/google/gofuzz"

	"github.com/abronan/valkeyrie/store"
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
	testCount         = 1000
	testCountBytesMin = 1
	testCountBytesMax = 1000
)

type TestType struct {
	A, B int64
	C    string
	D    float64
	E    []byte
}

func newMockStore(t *testing.T) store.Store {
	m := NewMock()
	return m
}

func TestNewCustomStore(t *testing.T) {
	m := newMockStore(t)
	// newTestCrypter(t)
	fs := fuzz.New().NumElements(32, 32)
	fs.Fuzz(&testSecret)

	st, err := NewCustomStore(m, GobCodec{}, []byte{1, 0}, testSecret)
	assert.Nil(t, err, "Err in NewCustomStore must be nil")
	assert.NotNil(t, st, "New custom store must not be nil")
}

func TestStore_PutAndGet(t *testing.T) {
	m := newMockStore(t)

	st, err := NewCustomStore(m, GobCodec{}, []byte{0, 1}, testSecret)
	Register(TestType{})
	assert.Nil(t, err, "Err in Put must be nil")
	assert.NotNil(t, st, "New custom store must not be nil")

	testData := map[string]TestType{}
	fb := fuzz.New().NilChance(0).NumElements(testCountBytesMin, testCountBytesMax)
	fm := fuzz.New().NilChance(0).NumElements(testCount, testCount).Funcs(
		func(i *string, c fuzz.Continue) {
			*i = c.RandString()
			for len(*i) == 0 {
				*i = c.RandString()
			}
		},
		func(i *[]byte, c fuzz.Continue) {
			fb.Fuzz(i)
		},
	)
	fm.Fuzz(&testData)
	assert.Greater(t, len(testData), testCount/2,
		"Must have greater than testCount/2 random test values")
	i := 0
	for k, v := range testData {
		err = st.Put(k, v, nil)
		assert.Nil(t, err, "Err in Put must be nil")
		if i == 3 {
			testKey = k
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

	for k, v := range testData {
		testValOut := TestType{}
		err = st.Get(k, &testValOut, nil)
		if !assert.Nil(t, err, "Err in Get must be nil") {
			fmt.Printf("Error encoded value is: %x\n", ms.kv[k])
			fmt.Printf("Error key is: %s\n", k)
			fmt.Printf("Error value is: %v\n", v)
		}
		assert.NotNil(t, testValOut, "Get value must not be nil")
		if !assert.Equal(t, v, testValOut, "Result Put->Get Value must be equal") {
			fmt.Printf("Not equal key is: %s\n", k)
			fmt.Printf("Not equal value is: %v\n", v)
			fmt.Printf("Not equal out value is: %v\n", testValOut)
		}

	}
}

func TestStore_PutAndGetOne(t *testing.T) {
	m := newMockStore(t)

	st, err := NewCustomStore(m, GobCodec{}, []byte{0, 1}, testSecret)
	assert.Nil(t, err, "Err in Put must be nil")
	assert.NotNil(t, st, "New custom store must not be nil")

	k := "testKey"
	v := []byte("super secret test value")
	err = st.Put(k, v, nil)
	assert.Nil(t, err, "Err in Put must be nil")

	ms := st.Store.(*Mock)
	mv := ms.kv[k]
	fmt.Printf("for key '%v' AES-GCM-256 encoded value is '%v'\n", testKey, mv)
	testValOut := []byte{}
	err = st.Get(k, &testValOut, nil)
	assert.Nil(t, err, "Err in Get must be nil")
	fmt.Printf("for key '%v' AES-GCM-256 decoded value is '%s'\n", testKey, string(testValOut))

	ct, err := NewCustomStore(m, GobCodec{}, []byte{1, 0}, testSecret)
	assert.Nil(t, err, "Err in Put must be nil")
	assert.NotNil(t, st, "New custom store must not be nil")

	err = ct.Put(k, v, nil)
	assert.Nil(t, err, "Err in Put must be nil")

	mcs := ct.Store.(*Mock)
	mv = mcs.kv[k]
	fmt.Printf("for key '%v' chacha20Poly1305 encoded value is '%v'\n", testKey, mv)
	testValOut = testValOut[:0]
	err = ct.Get(k, &testValOut, nil)
	assert.Nil(t, err, "Err in Get must be nil")
	fmt.Printf("for key '%v' chacha20Poly1305 decoded value is '%s'\n", testKey, string(testValOut))
}

func TestStore_List(t *testing.T) {
	m := newMockStore(t)

	st, err := NewCustomStore(m, GobCodec{}, []byte{1, 0}, testSecret)
	Register(TestType{})
	assert.Nil(t, err, "Err in Put must be nil")
	assert.NotNil(t, st, "New custom store must not be nil")

	testData := map[string]TestType{}
	fm := fuzz.New().NilChance(0).NumElements(testCount, testCount).Funcs(
		func(i *string, c fuzz.Continue) {
			*i = c.RandString()
			for len(*i) == 0 {
				*i = c.RandString()
			}
		},
	)
	fm.Fuzz(&testData)
	for k, v := range testData {
		err = st.Put(k, v, nil)
		assert.Nil(t, err, "Err in Put must be nil")
	}

	testType := []TestType{}
	retList, err := st.List(testKey, &testType, nil)
	assert.Nil(t, err, "Err in List must be nil")
	assert.NotNil(t, testType, "List value must not be nil")
	assert.NotNil(t, retList, "List return []ListPair must not be nil")
	assert.Equal(t, len(testData), len(retList),
		"In List returned slices length must be equal to length of"+
			" original test data")
	for _, v := range retList {
		assert.Equal(t, testData[v.key], v.value.(TestType))
	}
}
