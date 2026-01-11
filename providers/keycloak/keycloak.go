// Package keycloak implements the OAuth2 protocol for authenticating users
// through Keycloak.
package keycloak

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gomodul/auth"
	"golang.org/x/oauth2"
)

// New creates a new Keycloak provider, and sets up important connection details.
// You should always call `keycloak.New` to get a new Provider. Never try to create
// one manually.
//
// baseURL should be your Keycloak server URL (e.g., "https://keycloak.example.com")
// realm is your Keycloak realm name
func New(clientKey, secret, callbackURL, baseURL, realm string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		BaseURL:      baseURL,
		Realm:        realm,
		providerName: "keycloak",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `auth.Provider` for accessing Keycloak.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	BaseURL      string // Keycloak server URL
	Realm        string // Keycloak realm
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// Client returns an HTTP client to be used in all fetch operations.
func (p *Provider) Client() *http.Client {
	return auth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the keycloak package.
// This method exists to satisfy the Provider interface but does not
// perform any debugging operations for Keycloak.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Keycloak for an authentication endpoint.
func (p *Provider) BeginAuth(state string) (auth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

type keycloakUser struct {
	Sub               string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
	Picture           string `json:"picture"`
}

// FetchUser will go to Keycloak and access basic information about the user.
func (p *Provider) FetchUser(session auth.Session) (auth.User, error) {
	sess := session.(*Session)
	user := auth.User{
		Token: auth.Token{
			Access:    sess.AccessToken,
			Refresh:   sess.RefreshToken,
			ExpiresAt: sess.ExpiresAt,
		},
		Provider: p.Name(),
		RawData:  make(map[string]interface{}),
	}

	if user.Token.Access == "" {
		// Data is not yet retrieved, since accessToken is still empty.
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	// Keycloak userinfo endpoint
	userInfoURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", p.BaseURL, p.Realm)

	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Authorization", "Bearer "+sess.AccessToken)

	response, err := p.Client().Do(req)
	if err != nil {
		return user, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	responseBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return user, err
	}

	var u keycloakUser
	if err := json.Unmarshal(responseBytes, &u); err != nil {
		return user, err
	}

	// Extract the user data we got from Keycloak into our auth.User.
	user.UserID = u.Sub
	user.Email = u.Email
	user.FullName = u.Name
	user.FirstName = u.GivenName
	user.LastName = u.FamilyName
	user.NickName = u.PreferredUsername
	user.AvatarURL = u.Picture

	// Store the raw response data
	if err := json.Unmarshal(responseBytes, &user.RawData); err != nil {
		return user, err
	}

	return user, nil
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	authURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth", provider.BaseURL, provider.Realm)
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", provider.BaseURL, provider.Realm)

	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{},
	}

	if len(scopes) > 0 {
		c.Scopes = append(c.Scopes, scopes...)
	} else {
		c.Scopes = []string{"openid", "email", "profile"}
	}
	return c
}

// RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

// RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(auth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}
