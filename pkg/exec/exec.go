package exec

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var encrypt_key string = "very-unsecure-key123456789azerty"
var iv string = "1234567890123456"

func Run(command string) {
	cvlist := strings.Split(command, " ")
	cmd := exec.Command(cvlist[0], cvlist[1:]...)
	cmd.Env = MutateEnv(os.Environ())
	out, err := cmd.Output()
	if err != nil {
		return
	}
	fmt.Println(string(out))
}

func Encrypt(plaintext string) string {
	return Ase256(plaintext, encrypt_key, iv, len(iv))
}

func MutateEnv(env []string) []string {
	ans := make([]string, len(env))
	re := regexp.MustCompile(`SAFE_RUN_.*=.*`)
	var nv string
	var err error
	for _, v := range env {
		if re.MatchString(v) {
			kv := strings.Split(v, "=")
			kv[0] = strings.Replace(kv[0], "SAFE_RUN_", "", 1)
			kv[1], err = env_decrypt(kv[1])
			if err != nil {
				fmt.Println(err)
				return nil
			}
			nv = strings.Join(kv, "=")
		} else {
			nv = v
		}
		ans = append(ans, nv)
	}
	return ans
}
func env_decrypt(text string) (string, error) {
	plaintext := Asd256(text, encrypt_key, iv, len(iv))
	return plaintext, nil
}

func Ase256(plaintext string, key string, iv string, blockSize int) string {
	bKey := []byte(key)
	bIV := []byte(iv)
	bPlaintext := PKCS5Padding([]byte(plaintext), blockSize, len(plaintext))
	block, _ := aes.NewCipher(bKey)
	ciphertext := make([]byte, len(bPlaintext))
	mode := cipher.NewCBCEncrypter(block, bIV)
	mode.CryptBlocks(ciphertext, bPlaintext)
	return hex.EncodeToString(ciphertext)
}

func Asd256(encrypted string, key string, iv string, blockSize int) string {
	bKey := []byte(key)
	bIV := []byte(iv)
	cipherTextDecoded, err := hex.DecodeString(encrypted)
	if err != nil {
		panic(err)
	}
	block, _ := aes.NewCipher(bKey)
	mode := cipher.NewCBCDecrypter(block, bIV)
	mode.CryptBlocks([]byte(cipherTextDecoded), []byte(cipherTextDecoded))
	return string(cipherTextDecoded)
}

func PKCS5Padding(ciphertext []byte, blockSize int, after int) []byte {
	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func SetKey(key string) error {
	if len([]rune(key)) != 32 {
		return errors.New("key length must be 32")
	}
	encrypt_key = key
	return nil
}

func GetKey() string {
	return "haha, you wish"
}

func SetIV(iv string) error {
	if len([]rune(iv)) != 16 {
		return errors.New("key length must be 16")
	}
	iv = iv
	return nil
}

func GetIV() string {
	return "haha, you wish"
}
