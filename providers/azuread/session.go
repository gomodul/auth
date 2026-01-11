package azuread

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/gomodul/auth"
)

// Session is the implementation of `auth.Session` for accessing AzureAD.
type Session struct {
	AuthURL      string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Facebook provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", auth.ErrNoAuthUrlErrorMessage
	}

	return s.AuthURL, nil
}

// Authorize the session with AzureAD and return the access token to be stored for future use.
func (s *Session) Authorize(provider auth.Provider, params auth.Params) (string, error) {
	p := provider.(*Provider)
	token, err := p.config.Exchange(auth.ContextForClient(p.Client()), params.Get("code"))
	if err != nil {
		return "", err
	}

	if !token.Valid() {
		return "", auth.ErrInvalidTokenFromProvider
	}

	s.AccessToken = token.AccessToken
	s.RefreshToken = token.RefreshToken
	s.ExpiresAt = token.Expiry

	return token.AccessToken, err
}

// Marshal the session into a string
func (s Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s Session) String() string {
	return s.Marshal()
}

// UnmarshalSession wil unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (auth.Session, error) {
	session := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(session)
	return session, err
}
