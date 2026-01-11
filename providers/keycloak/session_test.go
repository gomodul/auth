package keycloak_test

import (
	"testing"

	"github.com/gomodul/auth"
	"github.com/gomodul/auth/providers/keycloak"
	"github.com/stretchr/testify/assert"
)

func Test_Implements_Session(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &keycloak.Session{}

	a.Implements((*auth.Session)(nil), s)
}

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &keycloak.Session{}

	_, err := s.GetAuthURL()
	a.Error(err)

	s.AuthURL = "/foo"

	url, _ := s.GetAuthURL()
	a.Equal(url, "/foo")
}

func Test_ToJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &keycloak.Session{}

	data := s.Marshal()
	a.Equal(data, `{"AuthURL":"","AccessToken":"","RefreshToken":"","ExpiresAt":"0001-01-01T00:00:00Z","IDToken":""}`)
}

func Test_String(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &keycloak.Session{}

	a.Equal(s.String(), s.Marshal())
}

func Test_SessionWithValues(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	s := &keycloak.Session{
		AuthURL:     "https://keycloak.example.com/auth",
		AccessToken: "access-token-123",
	}

	data := s.Marshal()
	a.Contains(data, "https://keycloak.example.com/auth")
	a.Contains(data, "access-token-123")
}
