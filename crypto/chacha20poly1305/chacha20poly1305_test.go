package chacha20poly1305

import (
	"testing"

	"github.com/karantin2020/svalkey/testutils"
	"github.com/karantin2020/svalkey/types"
)

func TestEncryptDecrypt(t *testing.T) {
	testutils.RunTestEncryptDecrypt(t, func(key []byte) (types.Crypter, error) {
		return New(key)
	})
}
