package aesgcm

import (
	"bytes"
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"testing"

	fuzz "github.com/google/gofuzz"

	"github.com/stretchr/testify/assert"

	"github.com/karantin2020/svalkey/testutils"
	"github.com/karantin2020/svalkey/types"
)

var (
	testMessage = []byte("Do not go gentle into that good night")
	testKey     *AESGCM
)

var (
	testMessages = [][]byte{}
	testKeys     = [testKeysCount]*AESGCM{}
)

const (
	testCount         = 1000
	testKeysCount     = 100
	testCountBytesMin = 1
	testCountBytesMax = 1000
)

func prepareTestMessages() {
	fb := fuzz.New().NilChance(0).NumElements(testCountBytesMin, testCountBytesMax)
	fm := fuzz.New().NilChance(0).NumElements(testCount, testCount).Funcs(
		func(i *[]byte, c fuzz.Continue) {
			fb.Fuzz(i)
		},
	)
	fm.Fuzz(&testMessages)
}

func prepareTestKeys(t *testing.T) {
	mrand.Seed(42)
	var err error
	for i := 0; i < testKeysCount; i++ {
		n := mrand.Intn(3)
		if n == 0 {
			testKeys[i], err = New(AES128)
		} else if n == 1 {
			testKeys[i], err = New(AES192)
		} else if n == 1 {
			testKeys[i], err = New(AES256)
		}
		assert.Nil(t, err, "aesgcm.New must not return error")
	}
	testKey = testKeys[mrand.Intn(testKeysCount)]
}

/*
 * The following tests verify the positive functionality of this package:
 * can an encrypted message be decrypted?
 */

func TestGenerateKeys(t *testing.T) {
	var err error
	_, err = GenerateKey(AES128)
	assert.Nil(t, err, "aesgcm.GenerateKey must not return error")
	_, err = GenerateKey(AES192)
	assert.Nil(t, err, "aesgcm.GenerateKey must not return error")
	_, err = GenerateKey(AES256)
	assert.Nil(t, err, "aesgcm.GenerateKey must not return error")
}

func TestPrepare(t *testing.T) {
	prepareTestMessages()
	prepareTestKeys(t)
}

func TestEncryptDecrypt(t *testing.T) {
	testutils.RunTestEncryptDecrypt(t, func(key []byte) (types.Crypter, error) {
		n := mrand.Intn(3)
		if n == 0 {
			return New(AES128)
		} else if n == 1 {
			return New(AES192)
		} else if n == 2 {
			return New(AES256)
		}
		return nil, fmt.Errorf("error create crypter")
	})
}

/*
 * The following tests verify the negative functionality of this package:
 * does it fail when it should?
 */

func prngTester(size int, testFunc func()) {
	prng := rand.Reader
	buf := &bytes.Buffer{}

	rand.Reader = buf
	defer func() { rand.Reader = prng }()

	for i := 0; i < size; i++ {
		tmp := make([]byte, i)
		buf.Write(tmp)
		testFunc()
	}
}

func TestPRNGFailures(t *testing.T) {
	n := mrand.Intn(2)
	var keySize AESSize
	if n == 0 {
		keySize = AES128
	} else if n == 1 {
		keySize = AES256
	}
	testFunc := func() {
		_, err := GenerateKey(keySize)
		assert.NotNil(t, err, "expected key generation failure with bad PRNG")
	}
	prngTester(int(keySize), testFunc)

	testFunc = func() {
		_, err := GenerateNonce()
		assert.NotNil(t, err, "expected nonce generation failure with bad PRNG")
	}
	prngTester(NonceSize, testFunc)

	testFunc = func() {
		_, err := testKey.Encrypt(testMessage)
		assert.NotNil(t, err, "expected encryption failure with bad PRNG")
	}
	prngTester(NonceSize, testFunc)
}

func TestDecryptFailures(t *testing.T) {
	targetLength := NonceSize

	for i := 0; i < targetLength; i++ {
		buf := make([]byte, i)
		_, err := testKey.Decrypt(buf)
		assert.NotNil(t, err, "expected decryption failure with bad message length")
	}

	var keySize AESSize
	var err error
	n := mrand.Intn(2)
	if n == 0 {
		keySize = AES128
	} else if n == 1 {
		keySize = AES256
	}
	otherKey, err := New(keySize)
	assert.Nil(t, err, "New must not return error")

	ct, err := testKey.Encrypt(testMessage)
	assert.Nil(t, err, "Encrypt must not return error")

	_, err = otherKey.Decrypt(ct)
	assert.NotNil(t, err, "decrypt should fail with wrong key")
}

func TestAESGCM_JSON(t *testing.T) {
	n, err := New(AES256)
	if err != nil {
		t.Fatalf("%v", err)
	}
	got, err := n.MarshalJSON()
	assert.Nil(t, err, "AESGCM MarshalJSON() must pass no error")
	assert.NotNil(t, got, "AESGCM MarshalJSON() must pass not nil byte slice")

	nn := &AESGCM{}
	err = nn.UnmarshalJSON(got)
	assert.Nil(t, err, "AESGCM UnmarshalJSON() must pass no error")
	assert.Equal(t, n.key, nn.key, "UnmarshalJSON key must be equal to origin key")
}

func TestAESGCM_MarshalJSON(t *testing.T) {
	n1, err := New(AES256)
	datKey, err := n1.MarshalJSON()
	assert.Nil(t, err, "Marshal must not return error")

	n2 := &AESGCM{}
	err = n2.UnmarshalJSON(datKey)
	assert.Nil(t, err, "Unmarshal must not return error")

	for _, m := range testMessages {
		ct, err := n1.Encrypt(m)
		assert.Nil(t, err, "Err in AESGCM.Encrypt must be nil")
		pt, err := n2.Decrypt(ct)
		assert.Nil(t, err, "Err in AESGCM.Decrypt must be nil")

		assert.Equal(t, m, pt, "Encrypted->Decrypted messages"+
			" must be equal to original messages")
	}
}
