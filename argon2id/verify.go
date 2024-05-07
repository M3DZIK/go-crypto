package argon2id

import "bytes"

// Verify verifies the given password against the given Argon2ID hash.
// Returns true if the password matches the hash, false otherwise.
func Verify(password []byte, hash *Hash) bool {
	hasher := Hasher{
		Memory:      hash.Memory,
		Iterations:  hash.Iterations,
		Parallelism: hash.Parallelism,
		HashLength:  uint32(len(hash.Hash)),
	}

	passwordHash := hasher.Hash(password, hash.Salt)

	return bytes.Equal(passwordHash.Hash, hash.Hash)
}
