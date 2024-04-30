package argon2id

import "bytes"

// Verify verifies the given password against the given Argon2ID hash.
// Returns true if the password matches the hash, false otherwise.
func Verify(password []byte, hash *Hash) bool {
	hasher := Hasher{
		memory:      hash.memory,
		iterations:  hash.iterations,
		parallelism: hash.parallelism,
		hashLength:  uint32(len(hash.hash)),
	}

	passwordHash := hasher.Hash(password, hash.salt)

	return bytes.Equal(passwordHash.hash, hash.hash)
}
