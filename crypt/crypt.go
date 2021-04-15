package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"os"
)

func Encrypt(valor string, cpf string) []byte {
	CRYPT_KEY := os.Getenv("CRYPT_KEY")
	key := []byte(cpf + CRYPT_KEY)
	plaintext := []byte(valor)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, aesgcm.NonceSize())

	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext
}

func Decrypt(ciphertext []byte, cpf string) string {
	CRYPT_KEY := os.Getenv("CRYPT_KEY")
	key := []byte(cpf + CRYPT_KEY)
	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)
	plaintext, _ := aesgcm.Open(nil, ciphertext[:aesgcm.NonceSize()], ciphertext[aesgcm.NonceSize():], nil)

	return string(plaintext)
}
