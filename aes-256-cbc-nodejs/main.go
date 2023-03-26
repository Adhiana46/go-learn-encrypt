package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

const (
	ENCKEY    = "0x12bd468B6EC92Cb28727C4c1a8eba4c581E5134c"
	TEXT      = "Dolor minim ad ad magna adipisicing eiusmod. Irure elit anim aute cillum ullamco esse do sunt laborum quis. Non adipisicing anim proident ad velit laboris do pariatur. Amet duis elit magna nulla exercitation commodo sint excepteur aliquip minim ea sit reprehenderit ad. Sunt in cupidatat fugiat Lorem. Et minim elit incididunt nisi magna enim deserunt exercitation fugiat aute non. Quis non enim commodo officia velit et aliqua excepteur ad sit non amet."
	blockSize = 16
)

func main() {
	// random iv
	iv := make([]byte, 16)
	rand.Read(iv)

	// random salt
	salt := make([]byte, 64)
	rand.Read(salt)

	// derive key: 32 byte key length - in assumption the masterkey is a cryptographic and NOT a password there is no need for
	// a large number of iterations. It may can replaced by HKDF
	key := pbkdf2.Key([]byte(ENCKEY), salt, 2145, 32, sha512.New)

	// AES 256 GCM Mode
	ciphertext, err := encrypt(iv, key, []byte(TEXT))
	if err != nil {
		panic(err)
	}
	cipherb64 := base64.StdEncoding.EncodeToString(append(salt[:], append(iv[:], ciphertext...)...))
	fmt.Println(cipherb64)

	// encrypt the given text

	// extract the auth tag
	// generate output
	// console.log(Buffer.concat([salt, iv, encrypted]).toString("base64"));
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
