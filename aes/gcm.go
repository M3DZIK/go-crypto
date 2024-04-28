package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// GcmNonceLength is the length of the nonce in the AES GCM algorithm.
const GcmNonceLength = 12

// EncryptGCM encrypts the given data using AES GCM algorithm with the given key.
func EncryptGCM(key []byte, data []byte) ([]byte, error) {
	// create a new cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// allocate memory
	cipherText := make([]byte, GcmNonceLength+len(data))

	// generate a random nonce
	nonce := cipherText[:GcmNonceLength]
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// encrypt the data
	cipherText = gcm.Seal(cipherText[:GcmNonceLength], nonce, data, nil)

	return cipherText, nil
}

// DecryptGCM decrypts the given data using AES GCM algorithm with the given key.
func DecryptGCM(key []byte, cipherText []byte) ([]byte, error) {
	// create a new cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// get nonce from the ciphertext
	nonce := cipherText[:GcmNonceLength]
	// get data from the ciphertext
	data := cipherText[GcmNonceLength:]

	return gcm.Open(nil, nonce, data, nil)
}
