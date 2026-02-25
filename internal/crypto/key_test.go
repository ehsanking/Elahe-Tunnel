package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	plaintext := []byte("Hello, World!")
	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text does not match plaintext. Got %s, want %s", decrypted, plaintext)
	}
}

func TestEncryptDecryptWithShortKey(t *testing.T) {
	key := []byte("shortkey")
	plaintext := []byte("Secret Message")

	_, err := Encrypt(plaintext, key)
	if err == nil {
		t.Error("Expected Encrypt to fail with short key, but it succeeded")
	}

	// For Decrypt, we need a valid ciphertext structure (nonce + data + tag)
	// But Decrypt calls splitKey first, so it should fail regardless of ciphertext.
	ciphertext := make([]byte, 50) 
	_, err = Decrypt(ciphertext, key)
	if err == nil {
		t.Error("Expected Decrypt to fail with short key, but it succeeded")
	}
}

func TestEncryptDecryptWithWrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()

	plaintext := []byte("Secret Message")
	ciphertext, err := Encrypt(plaintext, key1)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = Decrypt(ciphertext, key2)
	if err == nil {
		t.Error("Expected decryption to fail with wrong key, but it succeeded")
	}
}
