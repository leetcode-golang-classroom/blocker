package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePrivateKey(t *testing.T) {
	privKey := GeneratePrivateKey()
	assert.Equal(t, len(privKey.Bytes()), privKeyLen)
	pubKey := privKey.Public()
	assert.Equal(t, len(pubKey.Bytes()), pubKeyLen)
}

func TestPrivateKeySign(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	msg := []byte("foo bar baz")
	sig := privKey.Sign(msg)
	assert.True(t, sig.Verify(pubKey, msg))
	// Test with invalid msg
	assert.False(t, sig.Verify(pubKey, []byte("foo")))
	// Test with invalid pubkey
	invalidPrivKey := GeneratePrivateKey()
	invalidPubKey := invalidPrivKey.Public()
	assert.False(t, sig.Verify(invalidPubKey, msg))
}

func TestPublicKeyToAddress(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	address := pubKey.Address()
	assert.Equal(t, addressLen, len(address.Bytes()))
}

func TestNewPrivateKeyFromString(t *testing.T) {
	var (
		seed       = "a2d58532da215aeeb01bbdec554ff50f6dbb20d4101073779f151f690bf0e247"
		privKey    = NewPrivateKeyFromString(seed)
		addressStr = "253e604c177cf6b0e93ef24c1ef010ad309e4641"
	)
	assert.Equal(t, privKeyLen, len(privKey.Bytes()))
	address := privKey.Public().Address()
	assert.Equal(t, addressStr, address.String())
}
