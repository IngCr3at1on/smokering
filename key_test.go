package smokering_test

import (
	"crypto/aes"
	"testing"

	. "github.com/IngCr3at1on/smokering"
)

func TestKey(t *testing.T) {
	ring, block := newSmokering(t)

	const (
		note = "a test key"
		id   = "test"
	)
	key, err := ring.Key(id, note, block, aes.BlockSize, getRandomKey)
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

func TestKeyGobEncodeDecode(t *testing.T) {
	ring, block := newSmokering(t)

	const (
		note = "a test key"
		id   = "test"
	)
	key, err := ring.Key(id, note, block, aes.BlockSize, getRandomKey)
	ok(t, err)
	assert(t, key != nil, "key should be a new key")

	byt, err := key.GobEncode()
	ok(t, err)
	assert(t, byt != nil, "should return encoded key data")

	key = &Key{}
	err = key.GobDecode(byt)
	ok(t, err)

	assert(t, key.ID() == id, "key.ID() should return id")
	assert(t, key.GetNote() == note, "key.GetNote() should return note")
}

func TestKeyAsFromJson(t *testing.T) {
	ring, block := newSmokering(t)

	const (
		note = "a test key"
		id   = "test"
	)
	key, err := ring.Key(id, note, block, aes.BlockSize, getRandomKey)
	ok(t, err)
	assert(t, key != nil, "key should be a new key")

	byt, err := key.AsJSON()
	ok(t, err)
	assert(t, byt != nil, "shuld return json data")

	key = &Key{}
	err = key.FromJSON(byt)
	ok(t, err)

	assert(t, key.ID() == id, "key.ID() should return id")
	assert(t, key.GetNote() == note, "key.GetNote() should return note")
}
