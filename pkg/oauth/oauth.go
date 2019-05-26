package oauth

import (
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
		redirectIss: getRedirectIss(wellKnownURL)
	}
	return provider
}

func getRedirectIss(wellKnownURL string) string {
	// self.redirect_url = ''.join((self.authorize_url,
	// 	'?client_id=', self.client_id,
	// 	'&response_type=token',
	// 	'&scope=', 'openid ', self.scopes,
	// 	'&redirect_uri=', self.redirecturi,
	// 	'&state=state',
	// 	'&nonce=nonce'
	// 	))
	return ""
}

// Check if Authenticated
func (p *Provider) Check(res http.ResponseWriter, req *http.Request) bool {
	session, _ := p.store.Get(req, p.cookieName)

	userAgent := req.Header.Get("USER_AGENT")
	if strings.HasPrefix(userAgent, "Mozilla") {
		// Ok if already authenticated
		if session.Values["authenticated"].(bool) {
			return true
		}

		http.Redirect(res, req, p.redirectIss, 302)

	}

	return false
}
