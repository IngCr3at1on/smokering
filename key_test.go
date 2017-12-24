package smokering_test

import (
	"crypto/aes"
	"testing"
)

func TestSmokeringsKey(t *testing.T) {
	ring, block := newSmokerings(t)

	const (
		note = "a test key"
		id   = "test"
	)
	key, err := ring.New(id, note, block, aes.BlockSize, getRandomKey)
	ok(t, err)
	assert(t, key != nil, "key should be a new key")

	k, err := key.Decrypt(block, aes.BlockSize)
	ok(t, err)
	assert(t, k != nil, "k should be the decrypted key")

	key = ring.GetKey(id)
	assert(t, key != nil, "used keys should return")

	key.Disable()
	key = ring.GetKey(id)
	assert(t, key == nil, "disabled keys should not return")
}
