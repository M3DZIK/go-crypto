package aes

import "encoding/hex"

// Key is a type that represents AES encryption key
type Key []byte

// Encode returns the hexadecimal encoding of Key.
func (key Key) Encode() string {
	return hex.EncodeToString(key)
}

// DecodeKey return the Key decoded from the hexadecimal encoding.
func DecodeKey(key string) (Key, error) {
	return hex.DecodeString(key)
}
