package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
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

// GetProviderName is a function used to get the name of a provider
// for a given request. By default, this provider is fetched from
// the URL query string. If you provide it in a different way,
// assign your own function to this variable that returns the provider
// name for your request.
func GetProviderName(req *http.Request) (string, error) {
	// try to get it from the url param "provider"
	if p := req.URL.Query().Get("provider"); p != "" {
		return p, nil
	}

	// try to get it from the url param ":provider"
	if p := req.URL.Query().Get(":provider"); p != "" {
		return p, nil
	}

	// try to get it from the context's value of "provider" key
	if p, ok := mux.Vars(req)["provider"]; ok {
		return p, nil
	}

	//  try to get it from the go-context's value of "provider" key
	if p, ok := req.Context().Value("provider").(string); ok {
		return p, nil
	}

	// try to get it from the url param "provider", when req is routed through 'chi'
	if p := chi.URLParam(req, "provider"); p != "" {
		return p, nil
	}

	// try to get it from the route param for go >= 1.22
	if p := req.PathValue("provider"); p != "" {
		return p, nil
	}

	// try to get it from the go-context's value of providerContextKey key
	if p, ok := req.Context().Value(ProviderParamKey).(string); ok {
		return p, nil
	}

	// As a fallback, loop over the used providers, if we already have a valid session for any provider (ie. user has already begun authentication with a provider), then return that provider name
	providers := GetProviders()
	session, _ := Store.Get(req, SessionName)
	for _, provider := range providers {
		p := provider.Name()
		value := session.Values[p]
		if _, ok := value.(string); ok {
			return p, nil
		}
	}

	// if not found then return an empty string with the corresponding error
	return "", errors.New("you must select a provider")
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
