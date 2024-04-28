package aes_test

import (
	"encoding/hex"
	"go.medzik.dev/crypto/aes"
	"testing"
)

func TestEncryptGCM(t *testing.T) {
	key, _ := hex.DecodeString("82fd4cefd6efde36171900b469bae4e06863cb70f80b4e216e44eeb0cf30460b")
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
