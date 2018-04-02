package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

func encrypt(plaintext string, key string) (string, error) {
	encrypted, err := encryptBytes([]byte(plaintext), []byte(key))
	return string(encrypted[:]), err
}

func decrypt(plaintext string, key string) (string, error) {
	decryptedBytes, err := decryptBytes([]byte(plaintext), []byte(key))
	return string(decryptedBytes[:]), err
}

func encryptBytes(plaintext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptBytes(encrypted []byte, key []byte) ([]byte, error) {

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, encrypted := encrypted[:nonceSize], encrypted[nonceSize:]
	return gcm.Open(nil, nonce, encrypted, nil)
}
