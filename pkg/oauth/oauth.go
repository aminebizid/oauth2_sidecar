package oauth

import (
	"net/http"
	"strings"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/sessions"
	"github.com/lestrrat/go-jwx/jwk"
	uuid "github.com/satori/go.uuid"
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
	users  map[string]string
	mutex  = &sync.Mutex{}
)

// NewOauthProvider create an OAUTH provider instance
func NewOauthProvider(wellKnownURL, clientID, redirectURI, audience, scopes, sessionKey string) *Provider {
	users = make(map[string]string)
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

func (p *Provider) recieveToken(w http.ResponseWriter, r *http.Request) (bool, *jwt.StandardClaims, string, string) {
	tokens, ok := r.URL.Query()["token"]
	if !ok || len(tokens[0]) < 1 {
		log.Error("Url Param 'token' is missing")
		return false, nil, "", ""
	}
	token := tokens[0]
	states, ok := r.URL.Query()["state"]
	if !ok || len(states[0]) < 1 {
		log.Error("Url Param 'state' is missing")
		return false, nil, "", ""
	}
	state := states[0]
	if users[state] == "" {
		log.Errorf("Unknown user state %s", state)
		return false, nil, "", ""
	}
	log.Debugf(state)
	log.Debugf("Implicit flow: Token recieved : %s", token)
	ok, claims := p.parseToken(token)
	return ok, claims, token, state
}

func (p *Provider) getRedirIss(requestURI string) string {
	u1, _ := uuid.NewV4()
	mutex.Lock()
	users[u1.String()] = requestURI
	mutex.Unlock()
	return strings.Replace(p.redirectIss, "$state$", u1.String(), 1)
}

func (p *Provider) checkBrowser(w http.ResponseWriter, r *http.Request) (bool, *jwt.StandardClaims) {

	if r.RequestURI == "/signin-oidc" {
		p.redirect(w)
		return false, nil
	}

	if strings.HasPrefix(r.RequestURI, "/signin-token") {
		log.Debug("Token recieved")
		valid, claims, token, state := p.recieveToken(w, r)
		if valid {
			p.SetSession(w, r, "CLIENTID", claims.Subject)
			p.SetSession(w, r, "TOKEN", token)
			origin := users[state]
			mutex.Lock()
			delete(users, state)
			mutex.Unlock()
			log.Debugf("Redirecting to %s", origin)
			http.Redirect(w, r, origin, 302)
			return false, nil
		}
		return false, nil
	}

	token := p.GetSessionString(r, "TOKEN")
	if token != "" {
		ok, claims := p.parseToken(token)
		if ok {
			return true, claims
		}
		log.Debug("Token expired or not valid")
	}
	redir := p.getRedirIss(r.RequestURI)
	log.Debugf("Not authenticated redirecting to %s", redir)
	http.Redirect(w, r, redir, 302)
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
