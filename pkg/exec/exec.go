package exec

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"syscall"
)

func Run(command []string, detached bool, enc bool, privateKeyPath string) {
	fmt.Println("Running command ", command)
	env := MutateEnv(os.Environ(), enc, privateKeyPath)
	err := syscall.Exec(command[0], command, env)
	if err != nil {
		panic(err)
	}
}

func Encrypt(plaintext string, publicKeyPath string) string {
	pubKey := ReadPublicKeyFromFile(publicKeyPath)
	return EncryptRSA(plaintext, pubKey)
}

func Decrypt(plaintext string, privateKeyPath string) string {
	privKey := ReadPrivateKeyFromFile(privateKeyPath)
	text, err := DecryptRSA(plaintext, privKey)
	if err != nil {
		panic(err)
	}
	return text
}

func ReadPublicKeyFromFile(keyPath string) *rsa.PublicKey {
	pub, err := ioutil.ReadFile(keyPath)
	if err != nil {
		panic(err)
	}
	pubPem, _ := pem.Decode(pub)
	if pubPem == nil {
		panic(errors.New("rsa public key not in pem format"))
	}
	if pubPem.Type != "PUBLIC KEY" {
		panic("not a RSA public key")
	}
	parsedKey, err := x509.ParsePKIXPublicKey(pubPem.Bytes)
	if err != nil {
		panic(err)
	}
	var pubKey *rsa.PublicKey
	pubKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		panic("Cannot parse publicKey")
	}
	return pubKey
}

func ReadPrivateKeyFromFile(keyPath string) *rsa.PrivateKey {
	priv, err := ioutil.ReadFile(keyPath)
	if err != nil {
		panic(err)
	}
	privPem, _ := pem.Decode(priv)
	var privPemBytes []byte
	if privPem.Type != "RSA PRIVATE KEY" {
		panic(errors.New("not a RSA private key"))
	}
	privPemBytes = privPem.Bytes
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPemBytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privPemBytes); err != nil { // note this returns type `interface{}`
			panic(err)
		}
	}
	var privateKey *rsa.PrivateKey
	var ok bool
	privateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		panic(errors.New("cannot parse privateKey"))
	}
	return privateKey
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

func DecryptRSA(message string, privateKey *rsa.PrivateKey) (string, error) {
	messageBytes, err := hex.DecodeString(message)
	if err != nil {
		return "", err
	}
	decryptedBytes, err := privateKey.Decrypt(nil, messageBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		return "", err
	}
	return string(decryptedBytes), nil
}

func MutateEnv(env []string, onlyEncrypted bool, privateKeyPath string) []string {
	ans := make([]string, len(env))
	re := regexp.MustCompile(`SAFE_RUN_.*=.*`)
	privKey := ReadPrivateKeyFromFile(privateKeyPath)
	var nv string
	var err error
	for _, v := range env {
		if re.MatchString(v) {
			kv := strings.Split(v, "=")
			kv[0] = strings.Replace(kv[0], "SAFE_RUN_", "", 1)
			kv[1], err = env_decrypt(kv[1], privKey)
			if err != nil { // Error decrypting, we just add the variable as is (different key probably)
				if !onlyEncrypted {
					ans = append(ans, v)
				}
				continue
			}
			nv = strings.Join(kv, "=")
			ans = append(ans, nv)
		} else {
			if !onlyEncrypted {
				ans = append(ans, v)
			}
		}
	}
	return ans
}
func env_decrypt(text string, privKey *rsa.PrivateKey) (string, error) {
	plaintext, err := DecryptRSA(text, privKey)
	return plaintext, err
}

func PKCS5Padding(ciphertext []byte, blockSize int, after int) []byte {
	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}
