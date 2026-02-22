package auth

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// PasswordHasher defines the interface for password hashing operations
type PasswordHasher interface {
	// Hash generates a hash from the plain text password
	Hash(password string) (string, error)

	// Verify checks if the given password matches the hash
	Verify(password, hash string) bool

	// NeedsUpdate checks if the hash needs to be updated (e.g., cost parameter changed)
	NeedsUpdate(hash string) bool
}

// BcryptConfig holds configuration for bcrypt password hashing
type BcryptConfig struct {
	// Cost is the bcrypt cost factor (4-31, default 12)
	// Higher cost means more secure but slower hashing
	Cost int
}

// BcryptPasswordHasher implements password hashing using bcrypt
type BcryptPasswordHasher struct {
	config *BcryptConfig
}

// NewBcryptPasswordHasher creates a new bcrypt password hasher
func NewBcryptPasswordHasher(config *BcryptConfig) (*BcryptPasswordHasher, error) {
	if config == nil {
		config = &BcryptConfig{}
	}

	// Set default cost
	if config.Cost == 0 {
		config.Cost = 12
	}

	// Validate cost range
	if config.Cost < 4 {
		return nil, errors.New("bcrypt cost must be at least 4")
	}
	if config.Cost > 31 {
		return nil, errors.New("bcrypt cost must be at most 31")
	}

	return &BcryptPasswordHasher{config: config}, nil
}

// Hash generates a bcrypt hash from the plain text password
func (h *BcryptPasswordHasher) Hash(password string) (string, error) {
	if password == "" {
		return "", errors.New("password cannot be empty")
	}

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), h.config.Cost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(bytes), nil
}

// Verify checks if the given password matches the bcrypt hash
func (h *BcryptPasswordHasher) Verify(password, hash string) bool {
	if password == "" || hash == "" {
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// NeedsUpdate checks if the hash needs to be updated
// Returns true if the cost factor has changed
func (h *BcryptPasswordHasher) NeedsUpdate(hash string) bool {
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return true // Invalid hash, needs update
	}
	return cost != h.config.Cost
}

// PasswordService provides high-level password operations
type PasswordService struct {
	hasher PasswordHasher
}

// NewPasswordService creates a new password service with bcrypt as default
func NewPasswordService(hasher PasswordHasher) (*PasswordService, error) {
	if hasher == nil {
		// Use bcrypt as default
		var err error
		hasher, err = NewBcryptPasswordHasher(nil)
		if err != nil {
			return nil, err
		}
	}

	return &PasswordService{
		hasher: hasher,
	}, nil
}

// Hash generates a hash from the plain text password
func (s *PasswordService) Hash(password string) (string, error) {
	return s.hasher.Hash(password)
}

// Verify checks if the given password matches the hash
func (s *PasswordService) Verify(password, hash string) bool {
	return s.hasher.Verify(password, hash)
}

// NeedsUpdate checks if the hash needs to be updated
func (s *PasswordService) NeedsUpdate(hash string) bool {
	return s.hasher.NeedsUpdate(hash)
}

// ValidatePassword checks if a password meets security requirements
// Returns an error describing why the password is invalid
func ValidatePassword(password string) error {
	if password == "" {
		return errors.New("password cannot be empty")
	}

	// Minimum length
	const minLength = 8
	if len(password) < minLength {
		return fmt.Errorf("password must be at least %d characters", minLength)
	}

	// Maximum length (bcrypt limit)
	const maxLength = 72
	if len(password) > maxLength {
		return fmt.Errorf("password must be at most %d characters", maxLength)
	}

	return nil
}

// ValidateAndHash validates and hashes a password
func (s *PasswordService) ValidateAndHash(password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}

	return s.Hash(password)
}

// HashStrength represents the strength of a password hash
type HashStrength int

const (
	// HashStrengthWeak indicates weak hashing (cost < 10)
	HashStrengthWeak HashStrength = iota
	// HashStrengthMedium indicates medium hashing (cost 10-12)
	HashStrengthMedium
	// HashStrengthStrong indicates strong hashing (cost > 12)
	HashStrengthStrong
)

// GetHashStrength returns the strength of a bcrypt hash
func GetHashStrength(hash string) HashStrength {
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return HashStrengthWeak
	}

	if cost < 10 {
		return HashStrengthWeak
	}
	if cost <= 12 {
		return HashStrengthMedium
	}
	return HashStrengthStrong
}
