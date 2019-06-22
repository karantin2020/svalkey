package chacha20poly1305

import (
	"testing"

	"github.com/karantin2020/svalkey/testutils"
	"github.com/karantin2020/svalkey/types"
	"github.com/stretchr/testify/assert"
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

func TestNew(t *testing.T) {
	type args struct {
		key [][]byte
	}
	testKeys := testutils.GetRandomKeys(1000, 32, 32)
	testKeysMin := testutils.GetRandomKeys(1000, 1, 31)
	testKeysMax := testutils.GetRandomKeys(1000, 33, 1000)
	tests := []struct {
		name    string
		args    args
		want    func(t assert.TestingT, object interface{}, msgAndArgs ...interface{}) bool
		wantErr func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool
	}{
		{
			name:    "Test small byte slices as keys",
			args:    args{testKeysMin},
			want:    assert.Nil,
			wantErr: assert.Error,
		},
		{
			name:    "Test large byte slices as keys",
			args:    args{testKeysMax},
			want:    assert.Nil,
			wantErr: assert.Error,
		},
		{
			name:    "Test 32 byte slices as keys",
			args:    args{testKeys},
			want:    assert.NotNil,
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, j := range tt.args.key {
				got, err := New(j)
				tt.want(t, got, "New must return nil value")
				tt.wantErr(t, err, "New must return error")
			}
		})
	}
}
