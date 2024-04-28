package crypto_test

import (
	"go.medzik.dev/crypto"
	"testing"
)

func TestGenerateSalt(t *testing.T) {
	salt, err := crypto.GenerateSalt(16)
	if err != nil {
		t.Error(err)
	}

	if len(salt) != 16 {
		t.Error("salt length is not 16 bytes")
	}
}
