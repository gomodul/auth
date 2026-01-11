package keycloak_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/gomodul/auth"
	"github.com/gomodul/auth/providers/keycloak"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := keycloakProvider()
	a.Equal(provider.ClientKey, os.Getenv("KEYCLOAK_KEY"))
	a.Equal(provider.Secret, os.Getenv("KEYCLOAK_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
	a.Equal(provider.BaseURL, "https://keycloak.example.com")
	a.Equal(provider.Realm, "master")
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := keycloakProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*keycloak.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://keycloak.example.com/realms/master/protocol/openid-connect/auth")
	a.Contains(s.AuthURL, "client_id=")
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=openid+email+profile")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*auth.Provider)(nil), keycloakProvider())
}

func Test_Name(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := keycloakProvider()
	a.Equal("keycloak", provider.Name())
}

func Test_SetName(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := keycloakProvider()
	provider.SetName("custom-keycloak")
	a.Equal("custom-keycloak", provider.Name())
}

func Test_RefreshTokenAvailable(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := keycloakProvider()
	a.True(provider.RefreshTokenAvailable())
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := keycloakProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"https://keycloak.example.com/realms/master/protocol/openid-connect/auth","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*keycloak.Session)
	a.Equal(session.AuthURL, "https://keycloak.example.com/realms/master/protocol/openid-connect/auth")
	a.Equal(session.AccessToken, "1234567890")
}

func Test_CustomScopes(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := keycloak.New(
		os.Getenv("KEYCLOAK_KEY"),
		os.Getenv("KEYCLOAK_SECRET"),
		"/foo",
		"https://keycloak.example.com",
		"master",
		"openid", "email", "profile", "roles",
	)

	session, err := provider.BeginAuth("test_state")
	s := session.(*keycloak.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "scope=openid+email+profile+roles")
}

func Test_UserIDHandling(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	// Test Keycloak userinfo response format
	keycloakResponse := `{
		"sub":"123456789",
		"email":"test@example.com",
		"email_verified":true,
		"name":"Test User",
		"preferred_username":"testuser",
		"given_name":"Test",
		"family_name":"User"
	}`

	var user struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		GivenName         string `json:"given_name"`
		FamilyName        string `json:"family_name"`
	}
	err := json.Unmarshal([]byte(keycloakResponse), &user)
	a.NoError(err)
	a.Equal("123456789", user.Sub)
	a.Equal("test@example.com", user.Email)
	a.True(user.EmailVerified)
	a.Equal("Test User", user.Name)
	a.Equal("testuser", user.PreferredUsername)
	a.Equal("Test", user.GivenName)
	a.Equal("User", user.FamilyName)
}

func Test_MultipleRealms(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	// Test with different realm
	provider := keycloak.New(
		os.Getenv("KEYCLOAK_KEY"),
		os.Getenv("KEYCLOAK_SECRET"),
		"/foo",
		"https://keycloak.example.com",
		"myrealm",
	)

	session, err := provider.BeginAuth("test_state")
	s := session.(*keycloak.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/auth")
}

func keycloakProvider() *keycloak.Provider {
	return keycloak.New(
		os.Getenv("KEYCLOAK_KEY"),
		os.Getenv("KEYCLOAK_SECRET"),
		"/foo",
		"https://keycloak.example.com",
		"master",
	)
}
