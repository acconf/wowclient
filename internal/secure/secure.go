package secure

// ---------------------------------------
// THIS IS SIMPLE ENCRYPT/DECRYPT LOGIC.
// MUST TO REWRITE YOURSELF.
// Please refer to:
//   https://github.com/acconf/wowseckit
// ---------------------------------------
import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	SaltSize   = 16
	KeySize    = 32
	CRT_HEADER = "-----BEGIN RSA PRIVATE KEY-----"
	CRT_FOOTER = "-----END RSA PRIVATE KEY-----"
)

var (
	argon2Time    = uint32(1)     // LOOP TIME
	argon2Memory  = uint32(65536) // 64MB
	argon2Threads = uint8(4)      // THREADS
)

func parseToMap(multiLineData string) map[string]string {
	configMap := make(map[string]string)

	lines := strings.Split(multiLineData, "\n")

	for _, line := range lines {
		key, value, found := strings.Cut(line, "=")
		if found {
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			if key != "" {
				configMap[key] = value
			}
		}
	}
	return configMap
}

func parsePemText(ciphertext string) string {
	ciphertext = strings.ReplaceAll(ciphertext, CRT_HEADER, "")
	ciphertext = strings.ReplaceAll(ciphertext, CRT_FOOTER, "")
	ciphertext = strings.ReplaceAll(ciphertext, "\n", "")
	return strings.TrimSpace(ciphertext)
}

func deriveKeyFromPassword(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, KeySize)
}

func DecryptFile64(encryptedFilePath string) ([]byte, error) {

	encstr, err := os.ReadFile(encryptedFilePath)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(string(encstr), CRT_HEADER) || !strings.HasSuffix(string(encstr), CRT_FOOTER) {
		return nil, errors.New("INVALID ENCRYPT FILE FORMAT[11]")
	}
	pemstr := parsePemText(string(encstr))

	max_loop := 10
	cur_loop := 0
	finstr := ""
	for {
		cur_loop++
		if cur_loop > max_loop {
			return nil, errors.New("INVALID PEM FILE FORMAT[MAX ATTEMPT]")
		}
		encstr, err = base64.StdEncoding.DecodeString(pemstr)
		if err != nil {
			return nil, fmt.Errorf("INVALID PEM FILE FORMAT[L-%d] : %w", cur_loop, err)
		}
		if strings.Contains(string(encstr), "CHK = ") {
			finstr = string(encstr)
			break
		} else {
			pemstr = string(encstr)
		}
	}
	if finstr == "" {
		return nil, errors.New("INVALID PEM FILE FORMAT[99]]")
	}

	config := parseToMap(finstr)
	key1 := config["KEY"]
	encb64Str := config["ENC"]

	encData, err := base64.StdEncoding.DecodeString(encb64Str)
	if err != nil {
		return nil, fmt.Errorf("INVALID PEM DATA[LIC-99]: %w", err)
	}
	if len(key1) == 0 {
		return nil, errors.New("INVALID PEM DATA[SSN-99]")
	}

	gcmNonceSize := 12
	if len(encData) < (SaltSize + gcmNonceSize) {
		return nil, errors.New("INVALID PEM DATA[LEN-99]")
	}

	salt := encData[:SaltSize]
	nonce := encData[SaltSize : SaltSize+gcmNonceSize]
	ciphertext := encData[SaltSize+gcmNonceSize:]

	secretKey := base64.StdEncoding.EncodeToString([]byte(key1))
	key2 := deriveKeyFromPassword(secretKey, salt)

	block, err := aes.NewCipher(key2)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, ciphertext, nil)
}

// -------------- ENCRYPT LOGIC DO NOT PUT HERE ------------------------------
