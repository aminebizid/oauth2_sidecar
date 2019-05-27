package oauth

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/sessions"
)

// Provider structure
type Provider struct {
	wellKnownURL string
	clientID     string
	redirectURI  string
	audience     string
	scopes       string
	key          []byte
	store        *sessions.CookieStore
	cookieName   string
	redirectIss  string
}

type wellKnown struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

// NewOauthProvider create an OAUTH provider instance
func NewOauthProvider(wellKnownURL, clientID, redirectURI, audience, scopes string) *Provider {
	key := []byte("super-secret-key")
	provider := &Provider{
		wellKnownURL: wellKnownURL,
		clientID:     clientID,
		redirectURI:  redirectURI,
		audience:     audience,
		scopes:       scopes,
		key:          key,
		store:        sessions.NewCookieStore(key),
		cookieName:   "proxy_cookie",
		redirectIss:  getRedirectIss(wellKnownURL, clientID, scopes, redirectURI),
	}
	return provider
}

func getRedirectIss(wellKnownURL, clientID, scopes, redirectURI string) string {
	resp, error := http.Get(wellKnownURL)
	if error != nil {
		return ""
	}
	defer resp.Body.Close()
	var wellKnown wellKnown
	json.NewDecoder(resp.Body).Decode(&wellKnown)

	return wellKnown.AuthorizationEndpoint +
		"?client_id=" + clientID +
		"&response_type=token" +
		"&scope=openid " + scopes +
		"&redirect_uri=" + redirectURI +
		"&state=state" +
		"&nonce=nonce"
}

// Check if Authenticated
func (p *Provider) Check(res http.ResponseWriter, req *http.Request) bool {
	session, _ := p.store.Get(req, p.cookieName)

	userAgent := req.Header.Get("User-Agent")
	if strings.HasPrefix(userAgent, "Mozilla") {
		// Ok if already authenticated
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(res, req, p.redirectIss, 302)
		}

	}

	return false
}
