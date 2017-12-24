package smokering

import (
	"crypto/cipher"
	"sync"
)

type (
	// Smokering stores encryption keys protected by a master key.
	Smokering struct {
		mux *sync.RWMutex
		m   map[string]*Key
	}
)

// New returns a new Smokering encrypted with masterkey.
func New() *Smokering {
	return &Smokering{
		mux: &sync.RWMutex{},
		m:   make(map[string]*Key),
	}
}

// New adds a new key to the Smokering and returns it.
// block is the block cipher used to encrypt the keys (generally an AES cipher
// encrypted with a master key).
// blocksize is the size of the block used to encrypt the keys (e.g. aes.BlockSize)
// f is provided to generate the key.
func (kr *Smokering) New(id, note string, block cipher.Block, blocksize int, f func() ([]byte, error)) (*Key, error) {
	k, err := f()
	if err != nil {
		return nil, err
	}

	// TODO: if no ID is set generate one.

	key := &Key{
		ID:     id,
		mux:    &sync.RWMutex{},
		status: StatusNew,
	}

	if err := key.write(k, block, blocksize); err != nil {
		return nil, err
	}

	key.SetNote(note)
	kr.addKey(key)

	return key, nil
}

func (kr *Smokering) addKey(k *Key) {
	kr.mux.Lock()
	defer kr.mux.Unlock()

	kr.m[k.ID] = k
}

// GetKey gets a key from the keyring using it's ID.
func (kr *Smokering) GetKey(id string) *Key {
	return kr.getKey(id, false)
}

func (kr *Smokering) getKey(id string, disabled bool) *Key {
	kr.mux.RLock()
	defer kr.mux.RUnlock()

	k, ok := kr.m[id]
	if !ok {
		return nil
	}

	if k.status == StatusDisabled && !disabled {
		return nil
	}

	return k
}
