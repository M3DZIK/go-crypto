package crypto

import "crypto/rand"

func GenerateSalt(size int) ([]byte, error) {
	// allocate memory
	salt := make([]byte, size)

	// generate random bytes
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	return salt, nil
}
