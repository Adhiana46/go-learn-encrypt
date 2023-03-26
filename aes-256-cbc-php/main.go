package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	plaintext = "Ex dolore aliqua commodo do Lorem Lorem cillum dolor et. Ex dolore aliqua commodo do Lorem Lorem cillum dolor et. Ex dolore aliqua commodo do Lorem Lorem cillum dolor et. Ex dolore aliqua commodo do Lorem Lorem cillum dolor et."
	enckey    = "G+KbPeShVkYp3s6v9y$B&E)H@McQfTjW"
	blockSize = 16
)

func main() {
	h := sha256.New()
	h.Write([]byte(enckey))
	key := h.Sum(nil)

	fmt.Printf("Password=%s\n", hex.EncodeToString(key))

	// IV must be exact 16 chars (128 bit)
	iv := make([]byte, 16)

	encrypted, err := encrypt(iv, key, []byte(plaintext))
	if err != nil {
		panic(err)
	}

	decrypted, err := decrypt(iv, key, encrypted)
	if err != nil {
		panic(err)
	}

	encryptedB64 := base64.StdEncoding.EncodeToString(append(iv, encrypted...))

	fmt.Printf("plaintext=%s \n", plaintext)
	fmt.Printf("cipher=aes-256-cbc \n")
	fmt.Printf("encrypted=%s \n", encryptedB64)
	fmt.Printf("decrypted=%s \n", decrypted)
}

func encrypt(iv, key, plaintext []byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	plaintext = pkcs7pad256(plaintext)
	ciphertext = make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)
	return
}

func decrypt(iv, key, ciphertext []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext = make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	return pkcs7strip256(plaintext)
}

func pkcs7pad256(data []byte) []byte {
	dataLen := len(data)
	padLen := blockSize - dataLen%blockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)

	return append(data, padding...)
}

func pkcs7strip256(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("pkcs7strip256: Data is empty")
	}
	if length%blockSize != 0 {
		return nil, errors.New("pkcs7strip256: Data is not block-aligned")
	}
	padLen := int(data[length-1])
	ref := bytes.Repeat([]byte{byte(padLen)}, padLen)
	if padLen > blockSize || padLen == 0 || !bytes.HasSuffix(data, ref) {
		return nil, errors.New("pkcs7strip256: Invalid padding")
	}
	return data[:length-padLen], nil
}
