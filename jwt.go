package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTClaims represents the JWT claims structure
type JWTClaims struct {
	UserID    string   `json:"user_id"`
	Email     string   `json:"email"`
	FirstName string   `json:"first_name,omitempty"`
	LastName  string   `json:"last_name,omitempty"`
	Roles     []string `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

// JWTConfig holds the configuration for JWT service
type JWTConfig struct {
	// SecretKey is used for HMAC signing method
	SecretKey string

	// PrivateKeyPEM is used for RSA/ECDSA signing methods (PEM format)
	PrivateKeyPEM []byte

	// PublicKeyPEM is used for RSA/ECDSA verification (PEM format)
	PublicKeyPEM []byte

	// Issuer identifies the principal that issued the JWT
	Issuer string

	// Audience identifies the recipients that the JWT is intended for
	Audience []string

	// AccessTokenDuration is the lifetime of access tokens (default: 15 minutes)
	AccessTokenDuration time.Duration

	// RefreshTokenDuration is the lifetime of refresh tokens (default: 7 days)
	RefreshTokenDuration time.Duration

	// SigningMethod is the JWT signing method (default: HS256)
	// Options: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512
	SigningMethod jwt.SigningMethod
}

// JWTService provides JWT token generation and validation
type JWTService struct {
	config *JWTConfig
}

// NewJWTService creates a new JWT service
func NewJWTService(config *JWTConfig) (*JWTService, error) {
	if config == nil {
		return nil, ErrMissingSecret
	}

	// Set defaults
	if config.AccessTokenDuration == 0 {
		config.AccessTokenDuration = 15 * time.Minute
	}
	if config.RefreshTokenDuration == 0 {
		config.RefreshTokenDuration = 7 * 24 * time.Hour
	}
	if config.SigningMethod == nil {
		config.SigningMethod = jwt.SigningMethodHS256
	}

	// Validate configuration based on signing method
	switch config.SigningMethod.(type) {
	case *jwt.SigningMethodHMAC:
		if config.SecretKey == "" {
			return nil, ErrMissingSecret
		}
		// Validate secret key length (minimum 32 bytes for HS256)
		if len(config.SecretKey) < 32 {
			return nil, errors.New("secret key must be at least 32 bytes (256 bits) for secure HMAC signing")
		}
	case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA:
		if len(config.PrivateKeyPEM) == 0 || len(config.PublicKeyPEM) == 0 {
			return nil, errors.New("private and public keys are required for RSA/ECDSA signing")
		}
	default:
		if config.SecretKey == "" {
			return nil, ErrMissingSecret
		}
		// Validate secret key length (minimum 32 bytes)
		if len(config.SecretKey) < 32 {
			return nil, errors.New("secret key must be at least 32 bytes (256 bits) for secure HMAC signing")
		}
	}

	return &JWTService{config: config}, nil
}

// GenerateAccessToken generates a new access token for the given claims
func (s *JWTService) GenerateAccessToken(claims *JWTClaims) (string, error) {
	if claims == nil {
		return "", errors.New("claims cannot be nil")
	}

	now := time.Now()

	// Create standard claims
	standardClaims := jwt.RegisteredClaims{
		Issuer:    s.config.Issuer,
		Subject:   claims.UserID,
		Audience:  s.config.Audience,
		ExpiresAt: jwt.NewNumericDate(now.Add(s.config.AccessTokenDuration)),
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        generateTokenID(),
	}

	// Merge with custom claims
	claims.RegisteredClaims = standardClaims

	// Create token
	token := jwt.NewWithClaims(s.config.SigningMethod, claims)

	// Sign token
	return token.SignedString(s.getSigningKey())
}

// GenerateRefreshToken generates a new refresh token
func (s *JWTService) GenerateRefreshToken(userID string) (string, error) {
	now := time.Now()

	claims := &JWTClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.Issuer,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.RefreshTokenDuration)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        generateTokenID(),
		},
	}

	token := jwt.NewWithClaims(s.config.SigningMethod, claims)
	return token.SignedString(s.getSigningKey())
}

// GenerateTokenPair generates both access and refresh tokens
func (s *JWTService) GenerateTokenPair(claims *JWTClaims) (accessToken, refreshToken string, err error) {
	accessToken, err = s.GenerateAccessToken(claims)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err = s.GenerateRefreshToken(claims.UserID)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// ValidateToken validates a JWT token and returns the claims
func (s *JWTService) ValidateToken(tokenString string) (*JWTClaims, error) {
	if tokenString == "" {
		return nil, ErrInvalidToken
	}

	// Parse token
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if token.Method != s.config.SigningMethod {
			return nil, ErrInvalidSigningMethod
		}
		return s.getSigningKey(), nil
	})

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	// Extract claims
	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	// Check expiration
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, ErrTokenExpired
	}

	return claims, nil
}

// ValidateRefreshToken validates a refresh token
func (s *JWTService) ValidateRefreshToken(tokenString string) (string, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}

	return claims.UserID, nil
}

// RefreshAccessToken generates a new access token from a refresh token
func (s *JWTService) RefreshAccessToken(refreshToken string, userClaims *JWTClaims) (string, error) {
	// Validate refresh token
	userID, err := s.ValidateRefreshToken(refreshToken)
	if err != nil {
		return "", fmt.Errorf("invalid refresh token: %w", err)
	}

	// Ensure user ID matches
	if userClaims.UserID != userID {
		return "", errors.New("user ID mismatch")
	}

	// Generate new access token
	return s.GenerateAccessToken(userClaims)
}

// ExtractTokenFromHeader extracts JWT token from Authorization header
func ExtractTokenFromHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", errors.New("authorization header is empty")
	}

	// Check Bearer prefix
	const bearerPrefix = "Bearer "
	if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
		return "", errors.New("authorization header format must be 'Bearer {token}'")
	}

	return authHeader[len(bearerPrefix):], nil
}

// getSigningKey returns the signing key based on the signing method
func (s *JWTService) getSigningKey() interface{} {
	switch s.config.SigningMethod.(type) {
	case *jwt.SigningMethodHMAC:
		return []byte(s.config.SecretKey)
	default:
		// For RSA/ECDSA, you would need to parse the PEM key here
		// This is a simplified implementation
		if s.config.SecretKey != "" {
			return []byte(s.config.SecretKey)
		}
		return nil
	}
}

// generateTokenID generates a cryptographically secure unique token ID (jti)
func generateTokenID() string {
	// Generate 16 random bytes (128 bits)
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp if crypto/rand fails (should not happen in normal operation)
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	// Encode to base64 URL-safe format for compact representation
	return base64.RawURLEncoding.EncodeToString(b)
}
