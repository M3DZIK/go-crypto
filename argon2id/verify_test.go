package argon2id_test

import (
	"go.medzik.dev/crypto/argon2id"
	"testing"
)

func TestVerify(t *testing.T) {
	hash := "$argon2id$v=19$m=15360,t=2,p=1$bWVkemlrQGR1Y2suY29t$n7wCfzdczbjclMnpvw+t/4D+mCcCFUU+hm6Z85k81PQ"
	decodedHash, err := argon2id.Decode(hash)
	if err != nil {
		t.Error(err)
	}

	argon2id.Verify([]byte("medzik@duck.com"), decodedHash)
}
