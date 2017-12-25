package smokering

import (
	"bytes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
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
		sync.RWMutex

		id     string
		note   string
		status uint

		// Keys are stored in their encrypted state.
		k []byte
	}

	keydata struct {
		ID     string `json:"id"`
		Note   string `json:"note"`
		Status uint   `json:"status"`
		K      string `json:"k"`
	}
)

// ID returns the key ID.
func (k *Key) ID() string {
	k.RLock()
	defer k.RUnlock()

	return k.id
}

// GetNote gets the note from the key.
func (k *Key) GetNote() string {
	k.RLock()
	defer k.RUnlock()

	return k.note
}

// SetNote sets the note on the key.
func (k *Key) SetNote(note string) {
	k.Lock()
	defer k.Unlock()

	k.note = note
}

// GetStatus gets the current key status.
func (k *Key) GetStatus() uint {
	k.RLock()
	defer k.RUnlock()

	return k.status
}

// Decrypt and decode the key so that it may be used.
// block is the block cipher generated from the smokering master key.
func (k *Key) Decrypt(block cipher.Block, blocksize int) ([]byte, error) {
	k.RLock()
	defer k.RUnlock()

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
	k.Lock()
	defer k.Unlock()

	k.status = StatusDisabled
}

func (k *Key) write(rawkey []byte, block cipher.Block, blocksize int) (err error) {
	k.Lock()
	defer k.Unlock()

	rawkey = pad(rawkey, blocksize)
	k.k, err = encrypt(block, rawkey, blocksize)
	if err != nil {
		return err
	}

	return nil
}

func (k *Key) getData() *keydata {
	return &keydata{
		ID:     k.id,
		Note:   k.note,
		Status: k.status,
		K:      base64.StdEncoding.EncodeToString(k.k),
	}
}

// GobEncode implements the GobEncoder interface to allow saving a Key.
func (k *Key) GobEncode() ([]byte, error) {
	k.RLock()
	defer k.RUnlock()
	d := k.getData()

	buf := new(bytes.Buffer)
	encoder := gob.NewEncoder(buf)

	if err := encoder.Encode(d.ID); err != nil {
		return nil, err
	}

	if err := encoder.Encode(d.Note); err != nil {
		return nil, err
	}

	if err := encoder.Encode(d.Status); err != nil {
		return nil, err
	}

	if err := encoder.Encode(d.K); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// GobDecode implements the GobDecoder interface to allow restoring a key state.
func (k *Key) GobDecode(byt []byte) error {
	k.Lock()
	defer k.Unlock()
	d := keydata{}

	buf := bytes.NewBuffer(byt)
	decoder := gob.NewDecoder(buf)

	if err := decoder.Decode(&d.ID); err != nil {
		return err
	}

	if err := decoder.Decode(&d.Note); err != nil {
		return err
	}

	if err := decoder.Decode(&d.Status); err != nil {
		return err
	}

	if err := decoder.Decode(&d.K); err != nil {
		return err
	}

	k.id = d.ID
	k.note = d.Note
	k.status = d.Status
	_k, err := base64.StdEncoding.DecodeString(d.K)
	if err != nil {
		return err
	}

	k.k = _k

	return nil
}

// AsJSON returns the key data serialized as JSON to allow saving a Key.
func (k *Key) AsJSON() ([]byte, error) {
	k.RLock()
	defer k.RUnlock()
	d := k.getData()

	return json.Marshal(d)
}

// FromJSON sets the key data from JSON to allow restoring a key state.
func (k *Key) FromJSON(byt []byte) error {
	k.Lock()
	defer k.Unlock()
	d := keydata{}

	if err := json.Unmarshal(byt, &d); err != nil {
		return err
	}

	k.id = d.ID
	k.note = d.Note
	k.status = d.Status
	_k, err := base64.StdEncoding.DecodeString(d.K)
	if err != nil {
		return err
	}

	k.k = _k

	return nil
}
