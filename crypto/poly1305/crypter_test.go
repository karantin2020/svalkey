package poly1305

import (
	"testing"

	fuzz "github.com/google/gofuzz"

	"github.com/stretchr/testify/assert"

	"github.com/karantin2020/svalkey/testutils"
	"github.com/karantin2020/svalkey/types"
)

var (
	testMessages = [][]byte{}
)

const (
	testCount         = 1000
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

func TestEncryptDecrypt(t *testing.T) {
	testutils.RunTestEncryptDecrypt(t, func(key []byte) (types.Crypter, error) {
		return New()
	})
}

func TestPoly1305_Crypter_Negative1(t *testing.T) {
	p, err := New()
	assert.Nil(t, err, "New poly1305 must not pass error")
	for _, m := range testMessages {
		ct, err := p.Encrypt(m)
		assert.Nil(t, err, "Encrypt must not pass error")
		bp, err := New()
		assert.Nil(t, err, "New poly1305 must not pass error")
		pt, err := bp.Decrypt(ct)
		assert.NotNil(t, err, "Decrypt must pass error with bad key")
		assert.NotEqual(t, m, pt,
			"Result plaintext must not be equal to testMessage")
	}
}

func TestPoly1305_Crypter_Negative2(t *testing.T) {
	p, err := New()
	assert.Nil(t, err, "New poly1305 must not pass error")
	for _, m := range testMessages {
		ct, err := p.Encrypt(m)
		assert.Nil(t, err, "Encrypt must not pass error")
		ct[0] = 'e'
		ct[2] = '@'
		pt, err := p.Decrypt(ct)
		assert.NotNil(t, err, "Decrypt must pass error")

		assert.NotEqual(t, m, pt,
			"Result plaintext must not be equal to testMessage")

	}
}

func TestPoly1305_Crypter_Negative3(t *testing.T) {
	p, err := New()
	assert.Nil(t, err, "New poly1305 must not pass error")
	for _, m := range testMessages {
		ct, err := p.Encrypt(m)
		assert.Nil(t, err, "Encrypt must not pass error")
		ct[len(ct)-5] = 'e'
		ct[len(ct)-3] = '@'
		pt, err := p.Decrypt(ct)
		assert.NotNil(t, err, "Decrypt must pass error")

		assert.NotEqual(t, m, pt,
			"Result plaintext must not be equal to testMessage")
	}
}

func TestNew(t *testing.T) {
	p, err := New()
	assert.Nil(t, err, "New poly1305 must not pass error")
	assert.NotNil(t, p, "relult of New() must be not nil")
}
