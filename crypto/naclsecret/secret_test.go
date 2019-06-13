package naclsecret

import (
	"bytes"
	"crypto/rand"
	"testing"

	fuzz "github.com/google/gofuzz"

	"golang.org/x/crypto/nacl/secretbox"

	"github.com/stretchr/testify/assert"
)

var (
	testMessages [][]byte
	testKey      *NaClBox
)

const (
	testCount         = 1000
	testCountBytesMin = 10
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

/*
 * The following tests verify the positive functionality of this package:
 * can an encrypted message be decrypted?
 */

func TestGenerateKey(t *testing.T) {
	var err error
	testKey, err = New()
	assert.Nil(t, err, "New key must past no error")
	prepareTestMessages()
}

func TestEncrypt(t *testing.T) {
	for _, m := range testMessages {
		ct, err := testKey.Encrypt(m)
		assert.Nil(t, err, "Err in poly1305.Encrypt must be nil")

		pt, err := testKey.Decrypt(ct)
		assert.Nil(t, err, "Err in poly1305.Decrypt must be nil")

		assert.Equal(t, m, pt, "Encrypted->Decrypted messages"+
			" must be equal to original messages")
	}
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
	testFunc := func() {
		_, err := GenerateKey()
		if err == nil {
			t.Fatal("Err in poly1305.Encrypt: expected key generation failure with bad PRNG")
		}
	}
	prngTester(32, testFunc)

	testFunc = func() {
		_, err := GenerateNonce()
		if err == nil {
			t.Fatal("Err in poly1305.GenerateNonce: expected nonce generation failure with bad PRNG")
		}
	}
	prngTester(24, testFunc)

	testFunc = func() {
		for _, m := range testMessages {
			_, err := testKey.Encrypt(m)
			assert.NotNil(t, err, "Err in poly1305.Encrypt: expected encryption failure with bad PRN")
		}
	}
	prngTester(24, testFunc)
}

func TestDecryptFailures(t *testing.T) {
	targetLength := 24 + secretbox.Overhead

	for i := 0; i < targetLength; i++ {
		buf := make([]byte, i)
		if _, err := testKey.Decrypt(buf); err == nil {
			t.Fatal("expected decryption failure with bad message length")
		}
	}

	otherKey, err := New()
	if err != nil {
		t.Fatalf("%v", err)
	}

	for _, m := range testMessages {
		ct, err := testKey.Encrypt(m)
		assert.Nil(t, err, "Err in poly1305.Encrypt must be nil")

		_, err = otherKey.Decrypt(ct)
		assert.NotNil(t, err, "Err in poly1305.Decrypt negative must not be nil")
	}
}

func TestNaClBox_JSON(t *testing.T) {
	n, err := New()
	if err != nil {
		t.Fatalf("%v", err)
	}
	got, err := n.MarshalJSON()
	assert.Nil(t, err, "NaClBox MarshalJSON() must pass no error")
	assert.NotNil(t, got, "NaClBox MarshalJSON() must pass not nil byte slice")

	nn := &NaClBox{}
	err = nn.UnmarshalJSON(got)
	assert.Nil(t, err, "NaClBox UnmarshalJSON() must pass no error")
	assert.Equal(t, *n.key, *nn.key, "UnmarshalJSON key must be equal to origin key")
}
