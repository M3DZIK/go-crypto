package aes

import "encoding/hex"

// CipherText is a type that represents an encrypted cipher.
type CipherText []byte

// Encode returns the hexadecimal encoding of CipherText.
func (ciphertext CipherText) Encode() string {
	return hex.EncodeToString(ciphertext)
}

// DecodeCipherText return the CipherText decoded from the hexadecimal encoding.
func DecodeCipherText(ciphertext string) (CipherText, error) {
	return hex.DecodeString(ciphertext)
}
