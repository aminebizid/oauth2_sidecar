package oauth

import (
	"encoding/json"
	"net/http"
	"strings"

	log "github.com/Sirupsen/logrus"
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

func (p *Provider) redirect(res http.ResponseWriter) {
	html := `
		<html>
			<head>
				<script>
					try {
						x = location.hash.split('&');
						y = x[0].split('=');
						if (y[1] != '#access_token') {
							location.replace("/sign-error?error=forbidden");
						}
						token = y[1]
						console.log(token)
						location.replace("/signin-token?token=" + token);
					} catch(error) {
						location.replace("/sign-oidc?error=" + error);
					}
				</script>
			</head>
		</html>`
	res.Write([]byte(html))
}

func (p *Provider) recieveToken(req *http.Request) bool {
	tokens, ok := req.URL.Query()["token"]
	if !ok || len(tokens[0]) < 1 {
		log.Error("Url Param 'token' is missing")
		return false
	}
	return true
}

// Check if Authenticated
func (p *Provider) Check(res http.ResponseWriter, req *http.Request) bool {

	if req.RequestURI == "/signin-oidc" {
		p.redirect(res)
		return false
	}

	if strings.HasPrefix(req.RequestURI, "/signin-token") {
		return p.recieveToken(req)
	}

	userAgent := req.Header.Get("User-Agent")
	if strings.HasPrefix(userAgent, "Mozilla") {
		session, _ := p.store.Get(req, p.cookieName)
		// Ok if already authenticated
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(res, req, p.redirectIss, 302)
		}
	}

	return false
}
