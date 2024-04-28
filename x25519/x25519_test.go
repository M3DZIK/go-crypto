package x25519_test

import (
	"go.medzik.dev/crypto/x25519"
	"testing"
)

func TestPublicFromPrivate(t *testing.T) {
	privateKey, _ := x25519.DecodePrivateKey("3845bead1f44408ee436c742291f1362489eeaaa9daebd480b1c3e4bc528cb48")

	publicKey, _ := x25519.PublicFromPrivate(privateKey)
	if publicKey.Encode() != "9d49b72cf49defc6748c67ab274a1c2f096362ef3b2d691793686589760b4e25" {
		t.Error("public key is not correct")
	}
}

func TestComputeSharedSecret(t *testing.T) {
	ourKeys, _ := x25519.GenerateKey()
	theirKeys, _ := x25519.GenerateKey()

	sharedSecret, _ := x25519.ComputeSharedSecret(ourKeys.PrivateKey, theirKeys.PublicKey)
	theirSharedSecret, _ := x25519.ComputeSharedSecret(theirKeys.PrivateKey, ourKeys.PublicKey)

	if sharedSecret.Encode() != theirSharedSecret.Encode() {
		t.Error("shared secrets do not match")
	}
}

func TestComputeSharedSecret2(t *testing.T) {
	outPrivate, _ := x25519.DecodePrivateKey("3845bead1f44408ee436c742291f1362489eeaaa9daebd480b1c3e4bc528cb48")
	theirPublic, _ := x25519.DecodePublicKey("9d49b72cf49defc6748c67ab274a1c2f096362ef3b2d691793686589760b4e25")

	sharedSecret, _ := x25519.ComputeSharedSecret(outPrivate, theirPublic)
	if sharedSecret.Encode() != "2bebf3c397ab3c79db9aeeb2c1523ab4a32bd1ae335a19cd47e35983a5184d09" {
		t.Error("shared secrets is not correct")
	}
}
