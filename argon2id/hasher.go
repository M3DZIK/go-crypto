package argon2id

import (
	"golang.org/x/crypto/argon2"
)

// Hasher represents an Argon2ID hasher.
type Hasher struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	HashLength  uint32
}

// Hash computes the Argon2ID hash of the given password and salt.
func (hasher *Hasher) Hash(password []byte, salt []byte) Hash {
	hash := Hash{
		Salt:        salt,
		Memory:      hasher.Memory,
		Iterations:  hasher.Iterations,
		Parallelism: hasher.Parallelism,
	}

	hash.Hash = argon2.IDKey(password, hash.Salt, hash.Iterations, hash.Memory, hash.Parallelism, hasher.HashLength)

	return hash
}
