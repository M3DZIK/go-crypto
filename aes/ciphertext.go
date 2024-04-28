package aes

import "encoding/hex"

// EncodeCipherText encodes the given ciphertext into a hex string.
func EncodeCipherText(ciphertext []byte) string {
	return hex.EncodeToString(ciphertext)
}
