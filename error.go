package auth

import "errors"

var (
	// ErrInvalidToken is returned when token validation fails
	ErrInvalidToken = errors.New("invalid token")
	// ErrTokenExpired is returned when token has expired
	ErrTokenExpired = errors.New("token has expired")
	// ErrInvalidSigningMethod is returned when signing method is not HMAC
	ErrInvalidSigningMethod = errors.New("invalid signing method")

	// ErrRefreshTokenNotFound is returned when refresh token is not found
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	// ErrRefreshTokenRevoked is returned when refresh token has been revoked
	ErrRefreshTokenRevoked = errors.New("refresh token has been revoked")
	// ErrNoStorageConfigured is returned when no storage is configured
	ErrNoStorageConfigured = errors.New("no storage configured")

	// ErrMissingKey is returned when Key is empty
	ErrMissingKey = errors.New("config: Key is required")
	// ErrMissingSecret is returned when Secret is empty
	ErrMissingSecret = errors.New("config: Secret is required")
	// ErrMissingCallbackURL is returned when CallbackURL is empty
	ErrMissingCallbackURL = errors.New("config: CallbackURL is required")
	// ErrInvalidCallbackURL is returned when CallbackURL is not a valid URL
	ErrInvalidCallbackURL = errors.New("config: CallbackURL is not a valid URL")

	// ErrNoAuthUrlErrorMessage ...
	ErrNoAuthUrlErrorMessage = errors.New("an AuthURL has not been set")

	// ErrInvalidTokenFromProvider ...
	ErrInvalidTokenFromProvider = errors.New("invalid token received from provider")
)
