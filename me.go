/*
Package auth wraps common behaviour when using  This makes it quick, and easy, to get up
and running with  Of course, if you want complete control over how things flow, in regard
to the authentication process, feel free and use Auth directly.
*/
package auth

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gorilla/sessions"
)

var (
	// Store can/should be set by applications using auth. The default is a cookie store.
	Store        sessions.Store
	defaultStore sessions.Store

	keySet = false
)

type key int

// ProviderParamKey can be used as a key in context when passing in a provider
const ProviderParamKey key = iota

func init() {
	key := []byte(os.Getenv("SESSION_SECRET"))
	keySet = len(key) != 0

	cookieStore := sessions.NewCookieStore(key)
	cookieStore.Options.HttpOnly = true
	Store = cookieStore
	defaultStore = Store
}

/*
Handler is a convenience handler for starting the authentication process.
It expects to be able to get the name of the provider from the query parameters
as either "provider" or ":provider".

Handler will redirect the user to the appropriate authentication end-point
for the requested provider.
*/
func Handler(res http.ResponseWriter, req *http.Request) {
	url, err := GetAuthURL(res, req)
	if err != nil {
		res.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(res, err)
		return
	}

	http.Redirect(res, req, url, http.StatusTemporaryRedirect)
}

// SetState sets the state string associated with the given request.
// If no state string is associated with the request, one will be generated.
// This state is sent to the provider and can be retrieved during the
// callback.
func SetState(req *http.Request) string {
	state := req.URL.Query().Get("state")
	if len(state) > 0 {
		return state
	}

	// If a state query param is not passed in, generate a random
	// base64-encoded nonce so that the state on the auth URL
	// is unguessable, preventing CSRF attacks, as described in
	//
	// https://auth0.com/docs/protocols/oauth2/oauth-state#keep-reading
	nonceBytes := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, nonceBytes)
	if err != nil {
		panic("auth: source of randomness unavailable: " + err.Error())
	}
	return base64.URLEncoding.EncodeToString(nonceBytes)
}

// GetState gets the state returned by the provider during the callback.
// This is used to prevent CSRF attacks, see
// http://tools.ietf.org/html/rfc6749#section-10.12
func GetState(req *http.Request) string {
	params := req.URL.Query()
	if params.Encode() == "" && req.Method == http.MethodPost {
		return req.FormValue("state")
	}
	return params.Get("state")
}

/*
GetAuthURL starts the authentication process with the requested provided.
It will return a URL that should be used to send users to.

It expects to be able to get the name of the provider from the query parameters
as either "provider" or ":provider".

I would recommend using the BeginAuthHandler instead of doing all of these steps
yourself, but that's entirely up to you.
*/
func GetAuthURL(res http.ResponseWriter, req *http.Request) (string, error) {
	if !keySet && defaultStore == Store {
		fmt.Println("auth: no SESSION_SECRET environment variable is set. The default cookie store is not available and any calls will fail. Ignore this warning if you are using a different store.")
	}

	providerName, err := GetProviderName(req)
	if err != nil {
		return "", err
	}

	provider, err := GetProvider(providerName)
	if err != nil {
		return "", err
	}
	sess, err := provider.BeginAuth(SetState(req))
	if err != nil {
		return "", err
	}

	url, err := sess.GetAuthURL()
	if err != nil {
		return "", err
	}

	if err = StoreInSession(providerName, sess.Marshal(), req, res); err != nil {
		return "", err
	}

	return url, err
}

/*
CompleteUserAuth does what it says on the tin. It completes the authentication
process and fetches all the basic information about the user from the provider.

It expects to be able to get the name of the provider from the query parameters
as either "provider" or ":provider".
*/
func Me(res http.ResponseWriter, req *http.Request) (User, error) {
	if !keySet && defaultStore == Store {
		fmt.Println("auth: no SESSION_SECRET environment variable is set. The default cookie store is not available and any calls will fail. Ignore this warning if you are using a different store.")
	}

	providerName, err := GetProviderName(req)
	if err != nil {
		return User{}, err
	}

	provider, err := GetProvider(providerName)
	if err != nil {
		return User{}, err
	}

	value, err := GetFromSession(providerName, req)
	if err != nil {
		return User{}, err
	}
	defer Logout(res, req)

	sess, err := provider.UnmarshalSession(value)
	if err != nil {
		return User{}, err
	}

	if err = validateState(req, sess); err != nil {
		return User{}, err
	}

	user, err := provider.FetchUser(sess)
	if err == nil {
		// user can be found with existing session data
		return user, err
	}

	params := req.URL.Query()
	if params.Encode() == "" && req.Method == "POST" {
		req.ParseForm()
		params = req.Form
	}

	// get new token and retry fetch
	if _, err = sess.Authorize(provider, params); err != nil {
		return User{}, err
	}

	if err = StoreInSession(providerName, sess.Marshal(), req, res); err != nil {
		return User{}, err
	}

	gu, err := provider.FetchUser(sess)
	return gu, err
}

// validateState ensures that the state token param from the original
// AuthURL matches the one included in the current (callback) request.
func validateState(req *http.Request, sess Session) error {
	rawAuthURL, err := sess.GetAuthURL()
	if err != nil {
		return err
	}

	authURL, err := url.Parse(rawAuthURL)
	if err != nil {
		return err
	}

	reqState := GetState(req)

	originalState := authURL.Query().Get("state")
	if originalState != "" && (originalState != reqState) {
		return errors.New("state token mismatch")
	}
	return nil
}

// Logout invalidates a user session.
func Logout(res http.ResponseWriter, req *http.Request) error {
	session, err := Store.Get(req, SessionName)
	if err != nil {
		return err
	}
	session.Options.MaxAge = -1
	session.Values = make(map[interface{}]interface{})
	if err = session.Save(req, res); err != nil {
		return errors.New("Could not delete user session ")
	}
	return nil
}

// GetContextWithProvider returns a new request context containing the provider
func GetContextWithProvider(req *http.Request, provider string) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), ProviderParamKey, provider))
}

// StoreInSession stores a specified key/value pair in the session.
func StoreInSession(key string, value string, req *http.Request, res http.ResponseWriter) error {
	session, err := Store.New(req, SessionName)
	if err != nil {
		return err
	}

	if err = updateSessionValue(session, key, value); err != nil {
		return err
	}

	return session.Save(req, res)
}

// GetFromSession retrieves a previously-stored value from the session.
// If no value has previously been stored at the specified key, it will return an error.
func GetFromSession(key string, req *http.Request) (string, error) {
	session, err := Store.Get(req, SessionName)
	if err != nil {
		return "", err
	}
	value, err := getSessionValue(session, key)
	if err != nil {
		return "", errors.New("could not find a matching session for this request")
	}

	return value, nil
}

func getSessionValue(session *sessions.Session, key string) (string, error) {
	value := session.Values[key]
	if value == nil {
		return "", fmt.Errorf("could not find a matching session for this request")
	}

	rdata := strings.NewReader(value.(string))
	r, err := gzip.NewReader(rdata)
	if err != nil {
		return "", err
	}
	s, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}

	return string(s), nil
}

func updateSessionValue(session *sessions.Session, key, value string) error {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write([]byte(value)); err != nil {
		return err
	}
	if err := gz.Flush(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}

	session.Values[key] = b.String()
	return nil
}
