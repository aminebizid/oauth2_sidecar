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

var (
	jwkKey interface{}
)

// NewOauthProvider create an OAUTH provider instance
func NewOauthProvider(wellKnownURL, clientID, redirectURI, audience, scopes, sessionKey string) *Provider {
	key := []byte(sessionKey)
	wellKnown, err := getWellKnown(wellKnownURL)
	if err != nil {
		panic(err)
	}
	jwk, err := jwk.FetchHTTP(wellKnown.JwksURI)
	if err != nil {
		panic(err)
	}

	provider := &Provider{
		store:       sessions.NewCookieStore(key),
		cookieName:  "proxy_cookie",
		redirectIss: getRedirectIss(wellKnown.AuthorizationEndpoint, clientID, scopes, redirectURI),
		jwk:         jwk,
	}
	return provider
}

func (p *Provider) recieveToken(w http.ResponseWriter, r *http.Request) (bool, *jwt.StandardClaims, string) {
	tokens, ok := r.URL.Query()["token"]
	if !ok || len(tokens[0]) < 1 {
		log.Error("Url Param 'token' is missing")
		return false, nil, ""
	}
	token := tokens[0]
	log.Debugf("Implicit flow: Token recieved : %s", token)
	ok, claims := p.parseToken(token)
	return ok, claims, token
}

func (p *Provider) checkBrowser(w http.ResponseWriter, r *http.Request) (bool, *jwt.StandardClaims) {

	if r.RequestURI == "/signin-oidc" {
		p.redirect(w)
		return false, nil
	}

	if strings.HasPrefix(r.RequestURI, "/signin-token") {
		log.Debug("Token recieved")
		valid, claims, token := p.recieveToken(w, r)
		if valid {
			p.SetSession(w, r, "CLIENTID", claims.Subject)
			p.SetSession(w, r, "TOKEN", token)
			origin := p.GetSessionString(r, "origin_request")
			http.Redirect(w, r, origin, 302)
			return false, nil
		}
		return false, nil
	}

	p.SetSession(w, r, "origin_request", r.RequestURI)
	token := p.GetSessionString(r, "TOKEN")
	if token != "" {
		ok, claims := p.parseToken(token)
		if ok {
			return true, claims
		}
		log.Debug("Token expired or not valid")
	}
	log.Debugf("Not authenticated redirecting to %s", p.redirectIss)
	http.Redirect(w, r, p.redirectIss, 302)
	return false, nil
}

// Check if Authenticated
func (p *Provider) Check(w http.ResponseWriter, r *http.Request) (bool, *jwt.StandardClaims) {
	userAgent := r.Header.Get("User-Agent")
	if strings.HasPrefix(userAgent, "Mozilla") {
		return p.checkBrowser(w, r)
	}
	// Brearer
	bearer := r.Header.Get("Authorization")
	if bearer == "" {
		http.Error(w, "Unauthorized: No Authorization header", 401)
		return false, nil
	}
	splitToken := strings.Split(bearer, "Bearer ")
	if len(splitToken) != 2 {
		http.Error(w, "Unauthorized: No bearer detected", 401)
		return false, nil
	}
	log.Debug(splitToken[1])
	ok, claims := p.parseToken(splitToken[1])
	if !ok {
		http.Error(w, "Unauthorized: Invalid Token", 401)
	}
	return ok, claims
}
