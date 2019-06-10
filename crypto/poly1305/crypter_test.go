package poly1305

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testMessage = []byte("Do not go gentle into that good night.")
)

func TestPoly1305_Crypter(t *testing.T) {
	p := New()
	ct, err := p.Encrypt(testMessage)
	assert.Nil(t, err, "Encrypt must not pass error")
	assert.NotNil(t, ct, "Encrypt must not pass nil ciphertext")
	assert.NotEqual(t, ct, []byte{}, "Encrypt must not pass empty ciphertext")
	assert.LessOrEqual(t, len(testMessage)+p.key.NonceSize(), len(ct),
		"Encrypt must pass ciphertext with length of original message or more")

	pt, err := p.Decrypt(ct)
	assert.Nil(t, err, "Decrypt must not pass error")

	assert.Equal(t, testMessage, pt,
		"Result plaintext is not equal to testMessage")

}

func TestPoly1305_Crypter_Negative1(t *testing.T) {
	p := New()
	ct, err := p.Encrypt(testMessage)
	assert.Nil(t, err, "Encrypt must not pass error")
	bp := New()
	pt, err := bp.Decrypt(ct)
	assert.NotNil(t, err, "Decrypt must pass error with bad key")
	assert.NotEqual(t, testMessage, pt,
		"Result plaintext must not be equal to testMessage")
}

func TestPoly1305_Crypter_Negative2(t *testing.T) {
	p := New()
	ct, err := p.Encrypt(testMessage)
	assert.Nil(t, err, "Encrypt must not pass error")
	ct[0] = 'e'
	ct[2] = '@'
	pt, err := p.Decrypt(ct)
	assert.NotNil(t, err, "Decrypt must pass error")

	assert.NotEqual(t, testMessage, pt,
		"Result plaintext must not be equal to testMessage")
}

func TestPoly1305_Crypter_Negative3(t *testing.T) {
	p := New()
	ct, err := p.Encrypt(testMessage)
	assert.Nil(t, err, "Encrypt must not pass error")
	ct[len(ct)-5] = 'e'
	ct[len(ct)-3] = '@'
	pt, err := p.Decrypt(ct)
	assert.NotNil(t, err, "Decrypt must pass error")

	assert.NotEqual(t, testMessage, pt,
		"Result plaintext must not be equal to testMessage")
}

func TestNew(t *testing.T) {
	p := New()
	assert.NotNil(t, p, "relult of New() must be not nil")
}
