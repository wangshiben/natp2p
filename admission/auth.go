package admission

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const minimumBearerTokenLength = 32

// LoadBearerTokenFile 从文件读取测试或部署用 Bearer 凭据，避免凭据出现在进程参数或日志中。
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

// ValidateBearerToken 按 RFC 6750 字符集校验 Bearer Token，并拒绝长度不足的凭据。
// 本地测试环境默认生成 256 位随机 Token。
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
