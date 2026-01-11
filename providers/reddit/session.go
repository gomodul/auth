package reddit

import (
	"context"
	"encoding/json"
	"time"

	"github.com/gomodul/auth"
	"golang.org/x/oauth2"
)

type Session struct {
	AuthURL      string
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
}

func (s *Session) GetAuthURL() (string, error) {
	return s.AuthURL, nil
}

func (s *Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s *Session) Authorize(provider auth.Provider, params auth.Params) (string, error) {
	p := provider.(*Provider)
	t, err := p.config.Exchange(context.WithValue(context.Background(), oauth2.HTTPClient, p.client), params.Get("code"))
	if err != nil {
		return "", err
	}

	if !t.Valid() {
		return "", auth.ErrInvalidTokenFromProvider
	}

	s.AccessToken = t.AccessToken
	s.TokenType = t.TokenType
	s.RefreshToken = t.RefreshToken
	s.Expiry = t.Expiry

	return s.AccessToken, nil
}
