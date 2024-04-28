package aes_test

import (
	"go.medzik.dev/crypto/aes"
	"testing"
)

func TestEncryptGCM(t *testing.T) {
	key, _ := aes.DecodeKey("82fd4cefd6efde36171900b469bae4e06863cb70f80b4e216e44eeb0cf30460b")
	data := []byte("hello world")

	encryptedData, err := aes.EncryptGCM(key, data)
	if err != nil {
		t.Error(err)
	}

	decryptedData, err := aes.DecryptGCM(key, encryptedData)
	if err != nil {
		t.Error(err)
	}

	if string(decryptedData) != string(data) {
		t.Error("decrypted data is not the same as the original data")
	}
}

func TestDecryptGCM(t *testing.T) {
	key, _ := aes.DecodeKey("82fd4cefd6efde36171900b469bae4e06863cb70f80b4e216e44eeb0cf30460b")
	cipherText := "0996c65a72a60e748415dc6d32da1d4dcb65f41c71d4bec9554424218839b5d4b9d9195e5eea9d"
	decodedCipherText, _ := aes.DecodeCipherText(cipherText)

	clearText, err := aes.DecryptGCM(key, decodedCipherText)
	if err != nil {
		t.Error(err)
	}

	if string(clearText) != "hello world" {
		t.Error("decrypted data is not the same as the original data")
	}
}
