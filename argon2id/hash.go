package argon2id

// Hash represents the Argon2ID hash.
type Hash struct {
	hash        []byte
	salt        []byte
	memory      uint32
	iterations  uint32
	parallelism uint8
}
