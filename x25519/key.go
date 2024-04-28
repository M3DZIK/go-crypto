package x25519

import "encoding/hex"

// KeyPair represents a public/private key pair.
type KeyPair struct {
	PublicKey  PublicKey
	PrivateKey PrivateKey
}

// PublicKey represents a public key.
type PublicKey []byte

// Encode returns the hexadecimal encoding of PublicKey.
func (k *PublicKey) Encode() string {
	return hex.EncodeToString(*k)
}

// DecodePublicKey return the PublicKey decoded from the hexadecimal encoding.
func DecodePublicKey(key string) (PublicKey, error) {
	return hex.DecodeString(key)
}

type PrivateKey []byte

// Encode returns the hexadecimal encoding of PrivateKey.
func (k *PrivateKey) Encode() string {
	return hex.EncodeToString(*k)
}

// DecodePrivateKey return the PrivateKey decoded from the hexadecimal encoding.
func DecodePrivateKey(key string) (PrivateKey, error) {
	return hex.DecodeString(key)
}

// SharedSecret represents a shared secret.
type SharedSecret []byte

// Encode returns the hexadecimal encoding of SharedSecret.
func (s *SharedSecret) Encode() string {
	return hex.EncodeToString(*s)
}
