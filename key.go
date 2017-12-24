package smokering

import (
	"crypto/cipher"
	"sync"
)

const (
	// StatusUnknown should only ever be set on an improperly intialized key.
	StatusUnknown uint = iota
	// StatusNew is for a new key that has never been decrypted or used.
	StatusNew
	// StatusUsed is set on a key that's been decryted at least once.
	StatusUsed
	// StatusDisabled is set on a key that's been disabled.
	StatusDisabled
)

const (
	maxKnownStatus = StatusDisabled
)

type (
	// Key represents an encryption key.
	Key struct {
		// ID is an identifier for a key.
		ID string

		mux    *sync.RWMutex
		note   string
		status uint

		// Keys are stored in their encrypted state.
		k []byte
	}
)

// GetNote gets the note from the key.
func (k *Key) GetNote() string {
	k.mux.RLock()
	defer k.mux.RUnlock()

	return k.note
}

// SetNote sets the note on the key.
func (k *Key) SetNote(note string) {
	k.mux.Lock()
	defer k.mux.Unlock()

	k.note = note
}

// Decrypt and decode the key so that it may be used.
// block is the block cipher generated from the smokering master key.
func (k *Key) Decrypt(block cipher.Block, blocksize int) ([]byte, error) {
	k.mux.RLock()
	defer k.mux.RUnlock()

	paddedtext, err := decrypt(block, k.k, blocksize)
	if err != nil {
		return nil, err
	}

	k.status = StatusUsed

	return unpad(paddedtext, blocksize)
}

// Disable sets the status on a key to disabled, the keyring will not return it
// again after this.
func (k *Key) Disable() {
	k.mux.Lock()
	defer k.mux.Unlock()

	k.status = StatusDisabled
}

func (k *Key) write(rawkey []byte, block cipher.Block, blocksize int) (err error) {
	k.mux.Lock()
	defer k.mux.Unlock()

	rawkey = pad(rawkey, blocksize)
	k.k, err = encrypt(block, rawkey, blocksize)
	if err != nil {
		return err
	}

	return nil
}
