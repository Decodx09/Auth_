package utils

import "golang.org/x/crypto/bcrypt"

// HashPassword hashes a raw password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

// CheckPasswordHash compares a raw password and a hashed password
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
