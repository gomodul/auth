package auth

import "time"

// Token represents an authentication token
type Token struct {
	Access    string
	Refresh   string
	TokenType string // e.g., "Bearer"

	ExpiresAt time.Time
}
