package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// GenerateTOTPSecret generates a random base32 encoded secret for TOTP.
func GenerateTOTPSecret() (string, error) {
	secret := make([]byte, 10) // 80 bits
	_, err := rand.Read(secret)
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// GenerateTOTP generates a TOTP code for the given secret and time.
func GenerateTOTP(secret string, t time.Time) (string, error) {
	secret = strings.ToUpper(secret)
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		// Try with padding
		key, err = base32.StdEncoding.DecodeString(secret)
		if err != nil {
			return "", err
		}
	}

	// 30-second step
	step := t.Unix() / 30

	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, uint64(step))

	h := hmac.New(sha1.New, key)
	h.Write(msg)
	hash := h.Sum(nil)

	offset := hash[len(hash)-1] & 0x0f
	binaryCode := binary.BigEndian.Uint32(hash[offset : offset+4])
	binaryCode &= 0x7fffffff

	code := binaryCode % 1000000
	return fmt.Sprintf("%06d", code), nil
}

// ValidateTOTP checks if the provided code is valid for the current time (with a small window).
func ValidateTOTP(secret, code string) bool {
	now := time.Now()
	// Check current, previous, and next step to account for clock drift
	for i := -1; i <= 1; i++ {
		t := now.Add(time.Duration(i*30) * time.Second)
		validCode, err := GenerateTOTP(secret, t)
		if err == nil && validCode == code {
			return true
		}
	}
	return false
}
