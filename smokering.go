package smokering

import (
	"bytes"
	"crypto/cipher"
	"encoding/gob"
	"encoding/json"
	"errors"
	"sync"
)

type (
	// Smokering stores encryption keys protected by a master key.
	Smokering struct {
		sync.RWMutex
		m map[string]*Key
	}

	ringdata struct {
		M [][]byte `json:"M"`
	}
)

// New returns a new Smokering encrypted with master key.
func New() *Smokering {
	return &Smokering{
		m: make(map[string]*Key),
	}
}

// NewFromGob restores a Smokering from a Gob []byte.
func NewFromGob(byt []byte) (*Smokering, error) {
	sr := New()

	sr.Lock()
	defer sr.Unlock()
	d := ringdata{}

	buf := bytes.NewBuffer(byt)
	decoder := gob.NewDecoder(buf)

	if err := decoder.Decode(&d.M); err != nil {
		return nil, err
	}

	for _, kd := range d.M {
		if _, err := sr.keyFromGob(kd, true); err != nil {
			return nil, err
		}
	}

	return sr, nil
}

// NewFromJSON restores a Smokering from a JSON []byte.
func NewFromJSON(byt []byte) (*Smokering, error) {
	sr := New()

	sr.Lock()
	defer sr.Unlock()
	d := ringdata{}

	if err := json.Unmarshal(byt, &d); err != nil {
		return nil, err
	}

	for _, kd := range d.M {
		if _, err := sr.keyFromJSON(kd, true); err != nil {
			return nil, err
		}
	}

	return sr, nil
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
	// Until then, error if no ID is provided...
	if id == "" {
		return nil, errors.New("id cannot be empty")
	}

	key := &Key{
		id:     id,
		status: StatusNew,
	}

	if err := key.write(k, block, blocksize); err != nil {
		return nil, err
	}

	key.SetNote(note)
	sr.addKey(key, false)

	return key, nil
}

// KeyFromGob adds a key to the Smokering from Gob encoded key data, returning
// the key.
func (sr *Smokering) KeyFromGob(byt []byte) (*Key, error) {
	return sr.keyFromGob(byt, false)
}

func (sr *Smokering) keyFromGob(byt []byte, hasLock bool) (*Key, error) {
	key := &Key{}

	if err := key.GobDecode(byt); err != nil {
		return nil, err
	}

	sr.addKey(key, hasLock)

	return key, nil
}

// KeyFromJSON adds a key to the Smokering from JSON encoded key data, returning
// the key.
func (sr *Smokering) KeyFromJSON(byt []byte) (*Key, error) {
	return sr.keyFromJSON(byt, false)
}

func (sr *Smokering) keyFromJSON(byt []byte, hasLock bool) (*Key, error) {
	key := &Key{}

	if err := key.FromJSON(byt); err != nil {
		return nil, err
	}

	sr.addKey(key, hasLock)

	return key, nil
}

func (sr *Smokering) addKey(k *Key, hasLock bool) {
	if !hasLock {
		sr.Lock()
	}
	defer func() {
		if !hasLock {
			sr.Unlock()
		}
	}()

	sr.m[k.ID()] = k
}

// GetKey gets a key from the keyring using it's ID.
func (sr *Smokering) GetKey(id string) *Key {
	return sr.getKey(id, false)
}

func (sr *Smokering) getKey(id string, disabled bool) *Key {
	sr.RLock()
	defer sr.RUnlock()

	k, ok := sr.m[id]
	if !ok {
		return nil
	}

	if k.status == StatusDisabled && !disabled {
		return nil
	}

	return k
}

// GobEncode implements the GobEncoder interface to allow saving a Smokering.
func (sr *Smokering) GobEncode() ([]byte, error) {
	sr.RLock()
	defer sr.RUnlock()

	d := &ringdata{
		M: make([][]byte, 0),
	}

	for _, key := range sr.m {
		byt, err := key.GobEncode()
		if err != nil {
			return nil, err
		}

		d.M = append(d.M, byt)
	}

	buf := new(bytes.Buffer)
	encoder := gob.NewEncoder(buf)

	if err := encoder.Encode(d.M); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// AsJSON returns a Smokering's data serialized as JSON to allow saving a Smokering.
func (sr *Smokering) AsJSON() ([]byte, error) {
	sr.RLock()
	defer sr.RUnlock()

	d := &ringdata{
		M: make([][]byte, 0),
	}

	for _, key := range sr.m {
		byt, err := key.AsJSON()
		if err != nil {
			return nil, err
		}

		d.M = append(d.M, byt)
	}

	return json.Marshal(d)
}
