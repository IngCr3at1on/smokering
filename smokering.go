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

// New returns a new Smokering encrypted with master key.
func New() *Smokering {
	return &Smokering{
		mux: &sync.RWMutex{},
		m:   make(map[string]*Key),
	}
}

// Key adds a new key to the Smokering and returns it.
// block is the block cipher used to encrypt the keys (generally an AES cipher
// encrypted with a master key).
// blocksize is the size of the block used to encrypt the keys (e.g. aes.BlockSize)
// f is provided to generate the key.
func (sr *Smokering) Key(id, note string, block cipher.Block, blocksize int, f func() ([]byte, error)) (*Key, error) {
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
	sr.addKey(key)

	return key, nil
}

func (sr *Smokering) addKey(k *Key) {
	sr.mux.Lock()
	defer sr.mux.Unlock()

	sr.m[k.ID] = k
}

// GetKey gets a key from the keyring using it's ID.
func (sr *Smokering) GetKey(id string) *Key {
	return sr.getKey(id, false)
}

func (sr *Smokering) getKey(id string, disabled bool) *Key {
	sr.mux.RLock()
	defer sr.mux.RUnlock()

	k, ok := sr.m[id]
	if !ok {
		return nil
	}

	if k.status == StatusDisabled && !disabled {
		return nil
	}

	return k
}
