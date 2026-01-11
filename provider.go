package auth

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"golang.org/x/oauth2"
)

type (
	// Provider ...
	Provider interface {
		Name() string
		SetName(name string)

		FetchUser(Session) (User, error)

		BeginAuth(state string) (Session, error)
		UnmarshalSession(string) (Session, error)

		RefreshToken(refreshToken string) (*oauth2.Token, error) // Get new access token based on the refresh token
		RefreshTokenAvailable() bool                             // Refresh token is provided by auth provider or not

		Debug(bool)
	}
	Providers map[string]Provider
)

var (
	authSync      sync.RWMutex
	authProviders = Providers{}
)

// UseProviders adds a list of available providers for use with Auth.
// Can be called multiple times. If you pass the same provider more
// than once, the last will be used.
func UseProviders(viders ...Provider) {
	authSync.Lock()
	defer authSync.Unlock()

	for _, provider := range viders {
		authProviders[provider.Name()] = provider
	}
}

// GetProviders returns a copy of all the providers currently in use.
func GetProviders() Providers {
	return authProviders
}

// GetProvider returns a previously created provider. If Auth has not
// been told to use the named provider it will return an error.
func GetProvider(name string) (Provider, error) {
	authSync.RLock()
	provider := authProviders[name]
	authSync.RUnlock()
	if provider == nil {
		return nil, fmt.Errorf("no provider for %s exists", name)
	}
	return provider, nil
}

// ClearProviders will remove all providers currently in use.
// This is useful, mostly, for testing purposes.
func ClearProviders() {
	authSync.Lock()
	defer authSync.Unlock()

	authProviders = Providers{}
}

// ContextForClient provides a context for use with oauth2.
func ContextForClient(h *http.Client) context.Context {
	if h == nil {
		return context.TODO()
	}
	return context.WithValue(context.TODO(), oauth2.HTTPClient, h)
}

// HTTPClientWithFallBack to be used in all fetch operations.
func HTTPClientWithFallBack(h *http.Client) *http.Client {
	if h != nil {
		return h
	}
	return http.DefaultClient
}
