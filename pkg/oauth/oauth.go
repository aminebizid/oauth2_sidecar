package oauth

import (
	"net/http"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/sessions"
	"github.com/lestrrat/go-jwx/jwk"
)

// Provider structure
type Provider struct {
	store       *sessions.CookieStore
	cookieName  string
	redirectIss string
	jwk         *jwk.Set
}

type wellKnown struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JwksURI               string `json:"jwks_uri"`
}

type client struct {
	jwt.StandardClaims
}

// NewOauthProvider create an OAUTH provider instance
func NewOauthProvider(wellKnownURL, clientID, redirectURI, audience, scopes string) *Provider {
	key := []byte("super-secret-key")
	wellKnown := getWellKnown(wellKnownURL)
	jwk, _ := jwk.FetchHTTP(wellKnown.JwksURI)
	provider := &Provider{
		store:       sessions.NewCookieStore(key),
		cookieName:  "proxy_cookie",
		redirectIss: getRedirectIss(wellKnown.AuthorizationEndpoint, clientID, scopes, redirectURI),
		jwk:         jwk,
	}
	return provider
}

func (p *Provider) recieveToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	tokens, ok := r.URL.Query()["token"]
	if !ok || len(tokens[0]) < 1 {
		log.Error("Url Param 'token' is missing")
		return "", false
	}
	log.Debug(tokens[0])
	valid, subject := p.parseToken(tokens[0])
	if valid {
		log.Debug("Redirecting from token")

		return subject, true
	}
	return "", false

}

// Check if Authenticated
func (p *Provider) Check(w http.ResponseWriter, r *http.Request) (string, bool) {

	if r.RequestURI == "/signin-oidc" {
		p.redirect(w)
		return "", false
	}

	if strings.HasPrefix(r.RequestURI, "/signin-token") {
		log.Debug("Token recieved")
		client, valid := p.recieveToken(w, r)
		if valid {
			p.SetSession(w, r, "authenticated", true)
			p.SetSession(w, r, "CLIENTID", client)
			http.Redirect(w, r, p.GetSession(r, "origin_request").(string), 302)
			return client, valid
		}
		return client, valid
	}

	userAgent := r.Header.Get("User-Agent")
	if strings.HasPrefix(userAgent, "Mozilla") {
		p.SetSession(w, r, "origin_request", r.RequestURI)
		auth := p.GetSession(r, "authenticated")
		if auth != nil && auth.(bool) {
			client := p.GetSession(r, "CLIENTID")
			log.Debug("Authenticated")
			return client.(string), true
		}
		log.Debug("Not authenticated redirecting to " + p.redirectIss)
		http.Redirect(w, r, p.redirectIss, 302)
		return "", false
	}

	// Brearer
	bearer := r.Header.Get("Authorization")
	if bearer == "" {
		return "", false
	}
	splitToken := strings.Split(bearer, "Bearer ")
	log.Debug(splitToken[1])
	valid, subject := p.parseToken(splitToken[1])
	if valid {
		return subject, true
	}
	return "", false
}
