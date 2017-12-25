package smokering_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	. "github.com/IngCr3at1on/smokering"
)

func getRandomKey() ([]byte, error) {
	byt := make([]byte, 32)
	_, err := rand.Read(byt)
	return byt, err
}

func newSmokering(tb testing.TB) (*Smokering, cipher.Block) {
	ring := New()

	masterkey, err := getRandomKey()
	ok(tb, err)

	block, err := aes.NewCipher(masterkey)
	ok(tb, err)

	return ring, block
}

func TestSmokerings(t *testing.T) {
	ring, block := newSmokering(t)

	const (
		note = "a test key"
		id   = "test"
	)
	_, err := ring.Key(id, note, block, aes.BlockSize, getRandomKey)
	ok(t, err)

	key := ring.GetKey(id)
	assert(t, key != nil, "key should not be nil")

	equals(t, key.GetNote(), note)
}

func TestGobEncodeDecode(t *testing.T) {
	ring, block := newSmokering(t)

	const (
		note = "a test key"
		id   = "test"
	)
	_, err := ring.Key(id, note, block, aes.BlockSize, getRandomKey)
	ok(t, err)

	byt, err := ring.GobEncode()
	ok(t, err)
	assert(t, byt != nil, "it should return gob encoded bytes")

	ring, err = NewFromGob(byt)
	ok(t, err)
	assert(t, ring != nil, "it should decode the smokering from bytes")

	key := ring.GetKey(id)
	assert(t, key != nil, "it should return the test key")
	assert(t, key.GetNote() == "a test key", "the key note should be in tact")
}

func TestAsFromJson(t *testing.T) {
	ring, block := newSmokering(t)

	const (
		note = "a test key"
		id   = "test"
	)
	_, err := ring.Key(id, note, block, aes.BlockSize, getRandomKey)
	ok(t, err)

	byt, err := ring.AsJSON()
	ok(t, err)
	assert(t, byt != nil, "it should return json encoded bytes")

	ring, err = NewFromJSON(byt)
	ok(t, err)
	assert(t, ring != nil, "it should decode the smokering from bytes")

	key := ring.GetKey(id)
	assert(t, key != nil, "it should return the test key")
	assert(t, key.GetNote() == "a test key", "the key note should be in tact")
}
