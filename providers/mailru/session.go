package mailru

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/gomodul/auth"
)

// Session stores data during the auth process with MAILRU.
type Session struct {
	AuthURL      string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// GetAuthURL returns the URL for the authentication end-point for the provider.
func (s *Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", auth.ErrNoAuthUrlErrorMessage
	}

	return s.AuthURL, nil
}

// Marshal the session into a string
func (s *Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

// Authorize the session with MAILRU and return the access token to be stored for future use.
func (s *Session) Authorize(provider auth.Provider, params auth.Params) (string, error) {
	p := provider.(*Provider)
	token, err := p.oauthConfig.Exchange(auth.ContextForClient(p.Client()), params.Get("code"))
	if err != nil {
		return "", err
	}

	if !token.Valid() {
		return "", auth.ErrInvalidTokenFromProvider
	}

	s.AccessToken = token.AccessToken
	s.RefreshToken = token.RefreshToken
	s.ExpiresAt = token.Expiry

	return s.AccessToken, err
}

// UnmarshalSession will unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (auth.Session, error) {
	sess := new(Session)
	err := json.NewDecoder(strings.NewReader(data)).Decode(&sess)
	return sess, err
}
