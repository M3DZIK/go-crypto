package argon2id

// Hash represents the Argon2ID hash.
type Hash struct {
	Hash        []byte
	Salt        []byte
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
}
