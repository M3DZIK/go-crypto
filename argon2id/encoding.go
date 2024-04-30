package argon2id

import (
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strconv"
	"strings"
)

// Encode encodes the Argon2ID hash into a string representation.
func (hash *Hash) Encode() string {
	var sb strings.Builder

	sb.WriteString("$argon2id")
	sb.WriteString(fmt.Sprintf("$v=%d$m=%d,t=%d,p=%d", argon2.Version, hash.memory, hash.iterations, hash.parallelism))
	sb.WriteString(fmt.Sprintf("$%s", hash.salt))
	sb.WriteString(fmt.Sprintf("$%s", hash.hash))

	return sb.String()
}

// ErrInvalidHash is returned when an invalid hash is provided.
var ErrInvalidHash = errors.New("invalid hash")

// Decode decodes an Argon2ID hash from a string representation.
func Decode(encodedHash string) (*Hash, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, ErrInvalidHash
	}

	if parts[1] != "argon2id" {
		return nil, ErrInvalidHash
	}

	if parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return nil, ErrInvalidHash
	}

	performanceParams := strings.Split(parts[3], ",")
	if len(performanceParams) != 3 {
		return nil, ErrInvalidHash
	}

	hash := &Hash{}

	if strings.HasPrefix(performanceParams[0], "m=") {
		num, err := strconv.Atoi(performanceParams[0][2:])
		if err != nil {
			return nil, ErrInvalidHash
		}

		hash.memory = uint32(num)
	}

	if strings.HasPrefix(performanceParams[1], "t=") {
		num, err := strconv.Atoi(performanceParams[1][2:])
		if err != nil {
			return nil, ErrInvalidHash
		}

		hash.iterations = uint32(num)
	}

	if strings.HasPrefix(performanceParams[2], "p=") {
		num, err := strconv.Atoi(performanceParams[2][2:])
		if err != nil {
			return nil, ErrInvalidHash
		}

		hash.parallelism = uint8(num)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, ErrInvalidHash
	}

	hash.salt = salt

	hashBytes, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		fmt.Println("1")
		return nil, ErrInvalidHash
	}

	hash.hash = hashBytes

	return hash, nil
}
