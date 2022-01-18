package exec

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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

func Run(command []string, detached bool) {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = MutateEnv(os.Environ())
	if detached {
		err := cmd.Start()
		if err != nil {
			panic(err)
		}
		return
	}
	out, err := cmd.Output()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))
}

func Encrypt(plaintext string) string {
	return Ase256(plaintext, encrypt_key, iv, len(iv))
}

func Decrypt(plaintext string) string {
	return Asd256(plaintext, encrypt_key, iv, len(iv))
}

func EncryptRSA(message string, publicKey *rsa.PublicKey) string {
	bMessage := []byte(message)
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		bMessage,
		nil)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(encryptedBytes)
}

func DecryptRSA(message string, privateKey *rsa.PrivateKey) string {
	messageBytes, err := hex.DecodeString(message)
	if err != nil {
		panic(err)
	}
	decryptedBytes, err := privateKey.Decrypt(nil, messageBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		panic(err)
	}
	return string(decryptedBytes)
}

func MutateEnv(env []string) []string {
	ans := make([]string, len(env))
	re := regexp.MustCompile(`SAFE_RUN_.*=.*`)
	var nv string
	for _, v := range env {
		nv = v
		if re.MatchString(v) {
			kv := strings.Split(v, "=")
			kv[0] = strings.Replace(kv[0], "SAFE_RUN_", "", 1)
			kv[1] = env_decrypt(kv[1])
			nv = strings.Join(kv, "=")
		}
		ans = append(ans, nv)
	}
	return ans
}
func env_decrypt(text string) string {
	plaintext := Asd256(text, encrypt_key, iv, len(iv))
	return plaintext
}

func Ase256(plaintext string, key string, iv string, blockSize int) string {
	bKey := []byte(key)
	bIV := []byte(iv)
	bPlaintext := PKCS5Padding([]byte(plaintext), blockSize, len(plaintext))
	block, err := aes.NewCipher(bKey)
	if err != nil {
		panic(err)
	}
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
	block, err := aes.NewCipher(bKey)
	if err != nil {
		panic(err)
	}
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

func SetIV(newIv string) error {
	if len([]rune(newIv)) != 16 {
		return errors.New("key length must be 16")
	}
	iv = newIv
	return nil
}

func GetIV() string {
	return "haha, you wish"
}
