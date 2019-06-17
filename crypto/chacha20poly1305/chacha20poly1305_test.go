package chacha20poly1305

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/karantin2020/svalkey/testutils"
	"github.com/karantin2020/svalkey/types"
)

func TestEncryptDecrypt(t *testing.T) {
	testutils.RunTestEncryptDecrypt(t, func(key []byte) (types.Crypter, error) {
		return New(key)
	})
}

func TestChaCha20Poly1305_MarshalJSON_Positive(t *testing.T) {
	n, err := New(nil)
	if err != nil {
		t.Fatalf("%v", err)
	}
	got, err := n.MarshalJSON()
	assert.Nil(t, err, "ChaCha20Poly1305 MarshalJSON() must pass no error")
	assert.NotNil(t, got, "ChaCha20Poly1305 MarshalJSON() must pass not nil byte slice")

	nn := &XChaCha20Poly1305{}
	err = nn.UnmarshalJSON(got)
	assert.Nil(t, err, "ChaCha20Poly1305 UnmarshalJSON() must pass no error")
	assert.Equal(t, n.key, nn.key, "UnmarshalJSON key must be equal to origin key")
	testutils.RunTestEncryptDecryptPositive(t, n, nn)
}

func TestChaCha20Poly1305_MarshalJSON_Negative(t *testing.T) {
	n1, err := New(nil)
	assert.Nil(t, err, "New must not return error")

	n2, err := New(nil)
	assert.Nil(t, err, "New must not return error")

	testutils.RunTestEncryptDecryptNegative(t, n1, n2)
}
