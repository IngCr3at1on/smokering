package smokering

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

func pad(src []byte, size int) []byte {
	padding := size - len(src)%size
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func unpad(src []byte, size int) ([]byte, error) {
	if len(src) == 0 {
		return nil, errors.New("src must not be empty")
	}

	length := len(src)
	if length%size != 0 {
		return nil, fmt.Errorf("length %d not multiple of blocksize", length)
	}

	block := src[(length - size):]
	padlen := block[size-1]
	if padlen == 0 || int(padlen) > size {
		return nil, errors.New("invalid padding")
	}

	unpadding := size - int(padlen)
	if unpadding > length {
		return nil, errors.New("invalid encryption key")
	}

	return src[:(length - size + unpadding)], nil
}

func encrypt(block cipher.Block, paddedtext []byte, blocksize int) (ciphertext []byte, err error) {
	ciphertext = make([]byte, blocksize+len(paddedtext))
	iv := ciphertext[:blocksize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[blocksize:], paddedtext)
	return ciphertext, nil
}

func decrypt(block cipher.Block, ciphertext []byte, blocksize int) (paddedtext []byte, err error) {
	if len(ciphertext) < blocksize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:blocksize]
	if len(ciphertext)%blocksize != 0 {
		return nil, errors.New("ciphertext is not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	return ciphertext, nil
}
