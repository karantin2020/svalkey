package testutils

import (
	mrand "math/rand"
	"testing"

	fuzz "github.com/google/gofuzz"
	"github.com/karantin2020/svalkey/types"
	"github.com/stretchr/testify/assert"
)

var (
	testMessage = []byte("Do not go gentle into that good night")
	testSecret  types.Crypter
	testKey     []byte
)

var (
	testMessages = [][]byte{}
	testKeys     = [][]byte{}
	testSecrets  = [testSecretsCount]types.Crypter{}
)

const (
	testCount         = 1000
	testSecretsCount  = 100
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

func prepareTestKeys() {
	fb := fuzz.New().NilChance(0).NumElements(32, 32)
	fm := fuzz.New().NilChance(0).NumElements(testCount, testCount).Funcs(
		func(i *[]byte, c fuzz.Continue) {
			fb.Fuzz(i)
		},
	)
	fm.Fuzz(&testKeys)
}

func prepareTestSecrets(t *testing.T, fn func([]byte) (types.Crypter, error)) {
	var err error
	for i := 0; i < testSecretsCount; i++ {
		testSecrets[i], err = fn(testKeys[i])
		assert.Nil(t, err, "Crypter New must not return error")
	}
	testSecret = testSecrets[mrand.Intn(testSecretsCount)]
}

// RunTestEncryptDecrypt test encrypt->decrypt correctness
func RunTestEncryptDecrypt(t *testing.T, fn func([]byte) (types.Crypter, error)) {
	prepareTestMessages()
	prepareTestKeys()
	prepareTestSecrets(t, fn)
	for _, k := range testSecrets {
		for _, m := range testMessages {
			got, err := k.Encrypt(m)
			assert.Nil(t, err, "Crypter.Encrypt must not return error")
			assert.NotNil(t, got, "Crypter.Encrypt must not return nil value")

			pt, err := k.Decrypt(got)
			assert.Nil(t, err, "Crypter.Decrypt must not return error")
			assert.NotNil(t, got, "Crypter.Decrypt must not return nil value")
			assert.Equal(t, m, pt, "Decrypt must return original value")
		}
	}
}

// RunTestEncryptDecryptPositive tests decrypt with new key
func RunTestEncryptDecryptPositive(t *testing.T, old types.Crypter, new types.Crypter) {
	for _, m := range testMessages {
		got, err := old.Encrypt(m)
		assert.Nil(t, err, "Crypter.Encrypt must not return error")
		assert.NotNil(t, got, "Crypter.Encrypt must not return nil value")

		pt, err := new.Decrypt(got)
		assert.Nil(t, err, "Crypter.Decrypt must not return error")
		assert.NotNil(t, got, "Crypter.Decrypt must not return nil value")
		assert.Equal(t, m, pt, "Decrypt must return original value")
	}
}

// RunTestEncryptDecryptNegative tests decrypt with new key
func RunTestEncryptDecryptNegative(t *testing.T, old types.Crypter, new types.Crypter) {
	for _, m := range testMessages {
		got, err := old.Encrypt(m)
		assert.Nil(t, err, "Crypter.Encrypt must not return error")
		assert.NotNil(t, got, "Crypter.Encrypt must not return nil value")

		pt, err := new.Decrypt(got)
		assert.NotNil(t, err, "Crypter.Decrypt must return error")
		assert.NotEqual(t, m, pt, "Decrypt must not return original value")
	}
}
