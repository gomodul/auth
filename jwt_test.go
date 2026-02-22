package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJWTService(t *testing.T) {
	tests := []struct {
		name    string
		config  *JWTConfig
		wantErr error
	}{
		{
			name: "valid config with secret",
			config: &JWTConfig{
				SecretKey: "test-secret-key-32-bytes-long-min-32-bytes-long-min",
				Issuer:    "test-issuer",
			},
			wantErr: nil,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: ErrMissingSecret,
		},
		{
			name: "empty secret key",
			config: &JWTConfig{
				SecretKey: "",
			},
			wantErr: ErrMissingSecret,
		},
		{
			name: "config with custom durations",
			config: &JWTConfig{
				SecretKey:            "test-secret-key-32-bytes-long-min",
				AccessTokenDuration:  30 * time.Minute,
				RefreshTokenDuration: 30 * 24 * time.Hour,
			},
			wantErr: nil,
		},
		{
			name: "config with audience",
			config: &JWTConfig{
				SecretKey: "test-secret-key-32-bytes-long-min",
				Issuer:    "test-issuer",
				Audience:  []string{"api1", "api2"},
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := NewJWTService(tt.config)

			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.Nil(t, service)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, service)
			}
		})
	}
}

func TestJWTService_GenerateAccessToken(t *testing.T) {
	config := &JWTConfig{
		SecretKey: "test-secret-key-32-bytes-long-min",
		Issuer:    "test-issuer",
	}
	service, err := NewJWTService(config)
	require.NoError(t, err)

	claims := &JWTClaims{
		UserID:    "user123",
		Email:     "user@example.com",
		FirstName: "John",
		LastName:  "Doe",
		Roles:     []string{"user", "admin"},
	}

	token, err := service.GenerateAccessToken(claims)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Token should be a valid JWT with 3 parts
	parts := splitToken(token)
	assert.Len(t, parts, 3)
}

func TestJWTService_GenerateRefreshToken(t *testing.T) {
	config := &JWTConfig{
		SecretKey: "test-secret-key-32-bytes-long-min",
		Issuer:    "test-issuer",
	}
	service, err := NewJWTService(config)
	require.NoError(t, err)

	token, err := service.GenerateRefreshToken("user123")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestJWTService_GenerateTokenPair(t *testing.T) {
	config := &JWTConfig{
		SecretKey: "test-secret-key-32-bytes-long-min",
		Issuer:    "test-issuer",
	}
	service, err := NewJWTService(config)
	require.NoError(t, err)

	claims := &JWTClaims{
		UserID: "user123",
		Email:  "user@example.com",
		Roles:  []string{"user"},
	}

	accessToken, refreshToken, err := service.GenerateTokenPair(claims)
	assert.NoError(t, err)
	assert.NotEmpty(t, accessToken)
	assert.NotEmpty(t, refreshToken)
	assert.NotEqual(t, accessToken, refreshToken)
}

func TestJWTService_ValidateToken(t *testing.T) {
	config := &JWTConfig{
		SecretKey: "test-secret-key-32-bytes-long-min",
		Issuer:    "test-issuer",
	}
	service, err := NewJWTService(config)
	require.NoError(t, err)

	claims := &JWTClaims{
		UserID:    "user123",
		Email:     "user@example.com",
		FirstName: "John",
		LastName:  "Doe",
		Roles:     []string{"user", "admin"},
	}

	// Generate token
	token, err := service.GenerateAccessToken(claims)
	require.NoError(t, err)

	// Validate token
	validatedClaims, err := service.ValidateToken(token)
	assert.NoError(t, err)
	assert.NotNil(t, validatedClaims)
	assert.Equal(t, claims.UserID, validatedClaims.UserID)
	assert.Equal(t, claims.Email, validatedClaims.Email)
	assert.Equal(t, claims.FirstName, validatedClaims.FirstName)
	assert.Equal(t, claims.LastName, validatedClaims.LastName)
	assert.Equal(t, claims.Roles, validatedClaims.Roles)
}

func TestJWTService_ValidateToken_Invalid(t *testing.T) {
	config := &JWTConfig{
		SecretKey: "test-secret-key-32-bytes-long-min",
		Issuer:    "test-issuer",
	}
	service, err := NewJWTService(config)
	require.NoError(t, err)

	tests := []struct {
		name    string
		token   string
		wantErr error
	}{
		{
			name:    "empty token",
			token:   "",
			wantErr: ErrInvalidToken,
		},
		{
			name:    "invalid format",
			token:   "invalid.token",
			wantErr: ErrInvalidToken,
		},
		{
			name:    "malformed jwt",
			token:   "not.a.jwt",
			wantErr: ErrInvalidToken,
		},
		{
			name:    "wrong signature",
			token:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.wrong",
			wantErr: ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.ValidateToken(tt.token)
			assert.Error(t, err)
		})
	}
}

func TestJWTService_ValidateRefreshToken(t *testing.T) {
	config := &JWTConfig{
		SecretKey: "test-secret-key-32-bytes-long-min",
		Issuer:    "test-issuer",
	}
	service, err := NewJWTService(config)
	require.NoError(t, err)

	token, err := service.GenerateRefreshToken("user123")
	require.NoError(t, err)

	userID, err := service.ValidateRefreshToken(token)
	assert.NoError(t, err)
	assert.Equal(t, "user123", userID)
}

func TestJWTService_RefreshAccessToken(t *testing.T) {
	config := &JWTConfig{
		SecretKey: "test-secret-key-32-bytes-long-min",
		Issuer:    "test-issuer",
	}
	service, err := NewJWTService(config)
	require.NoError(t, err)

	// Generate refresh token
	refreshToken, err := service.GenerateRefreshToken("user123")
	require.NoError(t, err)

	// Create user claims
	userClaims := &JWTClaims{
		UserID: "user123",
		Email:  "user@example.com",
		Roles:  []string{"user"},
	}

	// Refresh access token
	newAccessToken, err := service.RefreshAccessToken(refreshToken, userClaims)
	assert.NoError(t, err)
	assert.NotEmpty(t, newAccessToken)

	// Validate new access token
	validatedClaims, err := service.ValidateToken(newAccessToken)
	assert.NoError(t, err)
	assert.Equal(t, userClaims.UserID, validatedClaims.UserID)
}

func TestExtractTokenFromHeader(t *testing.T) {
	tests := []struct {
		name      string
		authHeader string
		wantToken string
		wantErr   bool
	}{
		{
			name:      "valid bearer token",
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
			wantToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
			wantErr:   false,
		},
		{
			name:      "empty header",
			authHeader: "",
			wantErr:   true,
		},
		{
			name:      "missing bearer prefix",
			authHeader: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
			wantErr:   true,
		},
		{
			name:      "wrong prefix",
			authHeader: "Basic dXNlcjpwYXNz",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := ExtractTokenFromHeader(tt.authHeader)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantToken, token)
			}
		})
	}
}

// Helper function
func splitToken(token string) []string {
	parts := make([]string, 0)
	current := ""
	for _, c := range token {
		if c == '.' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
