package argon2id

import (
	"golang.org/x/crypto/argon2"
)

// Hasher represents an Argon2ID hasher.
type Hasher struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	hashLength  uint32
}

// Hash computes the Argon2ID hash of the given password and salt.
func (hasher *Hasher) Hash(password []byte, salt []byte) Hash {
	hash := Hash{
		salt:        salt,
		memory:      hasher.memory,
		iterations:  hasher.iterations,
		parallelism: hasher.parallelism,
	}

	hash.hash = argon2.IDKey(password, hash.salt, hash.iterations, hash.memory, hash.parallelism, hasher.hashLength)

	return hash
}
