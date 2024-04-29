package random_test

import (
	"go.medzik.dev/crypto/random"
	"testing"
)

func TestBytes(t *testing.T) {
	salt, err := random.Bytes(16)
	if err != nil {
		t.Error(err)
	}

	if len(salt) != 16 {
		t.Error("salt length is not 16 bytes")
	}
}
