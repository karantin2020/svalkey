package naclsecret

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/nacl/secretbox"

	"github.com/stretchr/testify/assert"
)

var (
	testMessage = []byte("Do not go gentle into that good night.")
	testKey     *NaClBox
)

/*
 * The following tests verify the positive functionality of this package:
 * can an encrypted message be decrypted?
 */

func TestGenerateKey(t *testing.T) {
	var err error
	testKey, err = New()
	assert.Nil(t, err, "New key must past no error")
}

func TestEncrypt(t *testing.T) {
	ct, err := testKey.Encrypt(testMessage)
	if err != nil {
		t.Fatalf("%v", err)
	}

	pt, err := testKey.Decrypt(ct)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(testMessage, pt) {
		t.Fatalf("messages don't match")
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
			t.Fatal("expected key generation failure with bad PRNG")
		}
	}
	prngTester(32, testFunc)

	testFunc = func() {
		_, err := GenerateNonce()
		if err == nil {
			t.Fatal("expected nonce generation failure with bad PRNG")
		}
	}
	prngTester(24, testFunc)

	testFunc = func() {
		_, err := testKey.Encrypt(testMessage)
		if err == nil {
			t.Fatal("expected encryption failure with bad PRNG")
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

	ct, err := testKey.Encrypt(testMessage)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if _, err = otherKey.Decrypt(ct); err == nil {
		t.Fatal("decrypt should fail with wrong key")
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
