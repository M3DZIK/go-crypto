package x25519

import (
	"crypto/ecdh"
	"crypto/rand"
)

// GenerateKey generates a new X25519 key pair.
func GenerateKey() (*KeyPair, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PublicKey:  key.PublicKey().Bytes(),
		PrivateKey: key.Bytes(),
	}, nil
}

// PublicFromPrivate returns the public key corresponding to the given private key.
func PublicFromPrivate(privateKey PrivateKey) (PublicKey, error) {
	key, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	return key.PublicKey().Bytes(), nil
}

// ComputeSharedSecret returns a shared secret between the two given keys.
func ComputeSharedSecret(outPrivate PrivateKey, theirPublic PublicKey) (SharedSecret, error) {
	ourKey, err := ecdh.X25519().NewPrivateKey(outPrivate)
	if err != nil {
		return nil, err
	}

	theirKey, err := ecdh.X25519().NewPublicKey(theirPublic)
	if err != nil {
		return nil, err
	}

	bytes, err := ourKey.ECDH(theirKey)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}
