package encryptor

import (
	"fmt"
	"testing"
)

// AES keys
const aes128Key string = "1234567812345678"
const aes192Key string = "123456781234567812345678"
const aes256Key string = "12345678123456781234567812345678"

// The value we're encrypting
const password string = "mypassword"

func TestEncryptAes128(t *testing.T) {
	encrypted, _ := Encrypt(password, aes128Key)
	decrypted, _ := Decrypt(encrypted, aes128Key)

	if decrypted != password {
		t.Errorf("Fail!  Expected: %s, Actual: %s", password, decrypted)
	}
}

func TestEncryptAes128WithWrongKey(t *testing.T) {
	encrypted, _ := Encrypt(password, aes128Key)
	_, err := Decrypt(encrypted, aes192Key)

	if err == nil {
		t.Errorf("Should have failed, wrong key")
	}
}

func TestEncryptAes192(t *testing.T) {
	encrypted, _ := Encrypt(password, aes192Key)
	decrypted, _ := Decrypt(encrypted, aes192Key)

	if decrypted != password {
		t.Errorf("Fail!  Expected: %s, Actual: %s", password, decrypted)
	}
}

func TestEncryptAes256(t *testing.T) {
	encrypted, _ := Encrypt(password, aes256Key)
	decrypted, _ := Decrypt(encrypted, aes256Key)

	if decrypted != password {
		t.Errorf("Fail!  Expected: %s, Actual: %s", password, decrypted)
	}
}

func TestEncryptKeyTooShort(t *testing.T) {
	_, err := Encrypt(password, "12345678")
	if err == nil {
		t.Error("Test should have errored")
	}
	fmt.Printf("PASSED: Caught key size error: %s\n", err)
}

func TestEncryptKeyTooLong(t *testing.T) {
	_, err := Encrypt(password, "1234567812345678123456781234567812345678")
	if err == nil {
		t.Error("Test should have errored")
	}
	fmt.Printf("PASSED: Caught key size error: %s\n", err)
}
