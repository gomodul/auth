package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBcryptPasswordHasher(t *testing.T) {
	tests := []struct {
		name    string
		config  *BcryptConfig
		wantErr bool
	}{
		{
			name:    "default config",
			config:  nil,
			wantErr: false,
		},
		{
			name: "custom cost",
			config: &BcryptConfig{
				Cost: 10,
			},
			wantErr: false,
		},
		{
			name: "cost too low",
			config: &BcryptConfig{
				Cost: 3,
			},
			wantErr: true,
		},
		{
			name: "cost too high",
			config: &BcryptConfig{
				Cost: 32,
			},
			wantErr: true,
		},
		{
			name: "cost at minimum",
			config: &BcryptConfig{
				Cost: 4,
			},
			wantErr: false,
		},
		{
			name: "cost at maximum",
			config: &BcryptConfig{
				Cost: 31,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher, err := NewBcryptPasswordHasher(tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, hasher)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, hasher)
			}
		})
	}
}

func TestBcryptPasswordHasher_Hash(t *testing.T) {
	hasher, err := NewBcryptPasswordHasher(nil)
	require.NoError(t, err)

	tests := []struct {
		name    string
		password string
		wantErr bool
	}{
		{
			name:    "valid password",
			password: "MySecurePassword123!",
			wantErr: false,
		},
		{
			name:    "short password",
			password: "pass",
			wantErr: false,
		},
		{
			name:    "long password",
			password: "ThisIsAVeryLongPasswordThatIsStillWithinTheBcryptLimitOf72Bytes",
			wantErr: false,
		},
		{
			name:    "empty password",
			password: "",
			wantErr: true,
		},
		{
			name:    "password with special chars",
			password: "!@#$%^&*()_+-=[]{}|;':\",./<>?",
			wantErr: false,
		},
		{
			name:    "password with unicode",
			password: "パスワード123",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := hasher.Hash(tt.password)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, hash)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, hash)
				// Bcrypt hash should be 60 characters
				assert.Len(t, hash, 60)
				// Should start with $2a$, $2b$, or $2y$
				assert.Regexp(t, `^\$2[aby]\$\d+\$`, hash)
			}
		})
	}
}

func TestBcryptPasswordHasher_Verify(t *testing.T) {
	hasher, err := NewBcryptPasswordHasher(nil)
	require.NoError(t, err)

	password := "MySecurePassword123!"
	hash, err := hasher.Hash(password)
	require.NoError(t, err)

	tests := []struct {
		name     string
		password string
		hash     string
		want     bool
	}{
		{
			name:     "correct password",
			password: password,
			hash:     hash,
			want:     true,
		},
		{
			name:     "incorrect password",
			password: "WrongPassword",
			hash:     hash,
			want:     false,
		},
		{
			name:     "empty password",
			password: "",
			hash:     hash,
			want:     false,
		},
		{
			name:     "different case",
			password: "mysecurepassword123!",
			hash:     hash,
			want:     false,
		},
		{
			name:     "invalid hash",
			password: password,
			hash:     "invalid-hash",
			want:     false,
		},
		{
			name:     "empty hash",
			password: password,
			hash:     "",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasher.Verify(tt.password, tt.hash)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestBcryptPasswordHasher_NeedsUpdate(t *testing.T) {
	// Create hasher with cost 12
	hasher12, err := NewBcryptPasswordHasher(&BcryptConfig{Cost: 12})
	require.NoError(t, err)

	// Create hasher with cost 10
	hasher10, err := NewBcryptPasswordHasher(&BcryptConfig{Cost: 10})
	require.NoError(t, err)

	password := "TestPassword123!"

	// Hash with cost 12
	hash12, err := hasher12.Hash(password)
	require.NoError(t, err)

	// Hash with cost 10
	hash10, err := hasher10.Hash(password)
	require.NoError(t, err)

	tests := []struct {
		name     string
		hasher   *BcryptPasswordHasher
		hash     string
		expected bool
	}{
		{
			name:     "same cost - no update needed",
			hasher:   hasher12,
			hash:     hash12,
			expected: false,
		},
		{
			name:     "different cost - update needed",
			hasher:   hasher12,
			hash:     hash10,
			expected: true,
		},
		{
			name:     "invalid hash - needs update",
			hasher:   hasher12,
			hash:     "invalid-hash",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.hasher.NeedsUpdate(tt.hash)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewPasswordService(t *testing.T) {
	tests := []struct {
		name    string
		hasher  PasswordHasher
		wantErr bool
	}{
		{
			name:    "default hasher",
			hasher:  nil,
			wantErr: false,
		},
		{
			name: "custom hasher",
			hasher: &mockHasher{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := NewPasswordService(tt.hasher)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, service)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, service)
			}
		})
	}
}

func TestPasswordService_Hash(t *testing.T) {
	hasher, err := NewBcryptPasswordHasher(nil)
	require.NoError(t, err)

	service, err := NewPasswordService(hasher)
	require.NoError(t, err)

	password := "TestPassword123!"
	hash, err := service.Hash(password)

	assert.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.Len(t, hash, 60)
}

func TestPasswordService_Verify(t *testing.T) {
	hasher, err := NewBcryptPasswordHasher(nil)
	require.NoError(t, err)

	service, err := NewPasswordService(hasher)
	require.NoError(t, err)

	password := "TestPassword123!"
	hash, err := service.Hash(password)
	require.NoError(t, err)

	// Correct password should verify
	result := service.Verify(password, hash)
	assert.True(t, result)

	// Wrong password should not verify
	result = service.Verify("WrongPassword", hash)
	assert.False(t, result)
}

func TestPasswordService_ValidateAndHash(t *testing.T) {
	hasher, err := NewBcryptPasswordHasher(nil)
	require.NoError(t, err)

	service, err := NewPasswordService(hasher)
	require.NoError(t, err)

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "valid password",
			password: "ValidPass123",
			wantErr:  false,
		},
		{
			name:     "too short",
			password: "short",
			wantErr:  true,
		},
		{
			name:     "empty",
			password: "",
			wantErr:  true,
		},
		{
			name:     "exactly 8 chars",
			password: "12345678",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := service.ValidateAndHash(tt.password)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, hash)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, hash)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "valid password",
			password: "MySecurePassword123!",
			wantErr:  false,
		},
		{
			name:     "too short",
			password: "short",
			wantErr:  true,
		},
		{
			name:     "empty",
			password: "",
			wantErr:  true,
		},
		{
			name:     "exactly 8 chars",
			password: "12345678",
			wantErr:  false,
		},
		{
			name:     "very long password (over 72 chars)",
			password: string(make([]byte, 73)), // bcrypt limit is 72 bytes
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetHashStrength(t *testing.T) {
	tests := []struct {
		name     string
		hash     string
		expected HashStrength
	}{
		{
			name:     "weak hash (cost 8)",
			hash:     "$2a$08$abcdefghijklmnopqrstuvwxyz12345678901234567890123456",
			expected: HashStrengthWeak,
		},
		{
			name:     "medium hash (cost 10)",
			hash:     "$2a$10$abcdefghijklmnopqrstuvwxyz12345678901234567890123456",
			expected: HashStrengthMedium,
		},
		{
			name:     "strong hash (cost 14)",
			hash:     "$2a$14$abcdefghijklmnopqrstuvwxyz12345678901234567890123456",
			expected: HashStrengthStrong,
		},
		{
			name:     "invalid hash",
			hash:     "invalid",
			expected: HashStrengthWeak,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetHashStrength(tt.hash)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Mock hasher for testing
type mockHasher struct{}

func (m *mockHasher) Hash(password string) (string, error) {
	return "mock-hash", nil
}

func (m *mockHasher) Verify(password, hash string) bool {
	return password == "correct" && hash == "mock-hash"
}

func (m *mockHasher) NeedsUpdate(hash string) bool {
	return false
}
