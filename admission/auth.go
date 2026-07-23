package admission

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const minimumBearerTokenLength = 32

// LoadBearerTokenFile reads a test/deployment bearer credential without ever
// placing the credential itself in process arguments or logs.
func LoadBearerTokenFile(filename string) (string, error) {
	if filename == "" {
		return "", errors.New("admission: bearer token file is empty")
	}
	encoded, err := os.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("admission: read bearer token file: %w", err)
	}
	if len(encoded) > 4096 {
		return "", errors.New("admission: bearer token exceeds 4096 bytes")
	}
	token := strings.TrimSpace(string(encoded))
	if err := ValidateBearerToken(token); err != nil {
		return "", err
	}
	return token, nil
}

// ValidateBearerToken accepts the RFC 6750 bearer alphabet and rejects short
// credentials. The local harness provisions 256-bit random tokens.
func ValidateBearerToken(token string) error {
	if len(token) < minimumBearerTokenLength {
		return fmt.Errorf("admission: bearer token must contain at least %d characters", minimumBearerTokenLength)
	}
	if len(token) > 4096 {
		return errors.New("admission: bearer token exceeds 4096 bytes")
	}
	padding := false
	for _, character := range token {
		if character == '=' {
			padding = true
			continue
		}
		valid := (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("-._~+/", character)
		if padding || !valid {
			return errors.New("admission: bearer token contains an invalid character")
		}
	}
	return nil
}
