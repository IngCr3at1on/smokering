package smokering_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	. "github.com/ingcr3at1on/smokering"
)

func getRandomKey() ([]byte, error) {
	byt := make([]byte, 32)
	_, err := rand.Read(byt)
	return byt, err
}

func newSmokerings(tb testing.TB) (*Smokering, cipher.Block) {
	ring := New()

	masterkey, err := getRandomKey()
	ok(tb, err)

	block, err := aes.NewCipher(masterkey)
	ok(tb, err)

	return ring, block
}

func TestSmokerings(t *testing.T) {
	ring, block := newSmokerings(t)

	const (
		note = "a test key"
		id   = "test"
	)
	_, err := ring.New(id, note, block, aes.BlockSize, getRandomKey)
	ok(t, err)

	key := ring.GetKey(id)
	assert(t, key != nil, "key should not be nil")

	equals(t, key.GetNote(), note)
}
