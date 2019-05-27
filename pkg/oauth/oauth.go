package oauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/sessions"
	"github.com/lestrrat/go-jwx/jwk"
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
	jwksURI      string
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
	provider := &Provider{
		wellKnownURL: wellKnownURL,
		clientID:     clientID,
		redirectURI:  redirectURI,
		audience:     audience,
		scopes:       scopes,
		key:          key,
		store:        sessions.NewCookieStore(key),
		cookieName:   "proxy_cookie",
		redirectIss:  getRedirectIss(wellKnown.AuthorizationEndpoint, clientID, scopes, redirectURI),
		jwksURI:      wellKnown.JwksURI,
	}
	return provider
}

func getWellKnown(wellKnownURL string) wellKnown {
	resp, _ := http.Get(wellKnownURL)

	defer resp.Body.Close()
	var wellKnown wellKnown
	json.NewDecoder(resp.Body).Decode(&wellKnown)
	return wellKnown
}

func getRedirectIss(authorizationEndpoint, clientID, scopes, redirectURI string) string {

	return authorizationEndpoint +
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
						location.replace("/signin-token?token=" + token);
					} catch(error) {
						location.replace("/sign-oidc?error=" + error);
					}
				</script>
			</head>
		</html>`
	res.Write([]byte(html))
}

func (p *Provider) getKey(token *jwt.Token) (interface{}, error) {

	// TODO: cache response so we don't have to make a request every time
	// we want to verify a JWT
	set, err := jwk.FetchHTTP(p.jwksURI)
	if err != nil {
		return nil, err
	}

	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have string kid")
	}

	if key := set.LookupKeyID(keyID); len(key) == 1 {
		return key[0].Materialize()
	}

	return nil, errors.New("unable to find key")
}

func (p *Provider) recieveToken(req *http.Request) bool {
	tokens, ok := req.URL.Query()["token"]
	if !ok || len(tokens[0]) < 1 {
		log.Error("Url Param 'token' is missing")
		return false
	}

	var client client
	token, _ := jwt.ParseWithClaims(tokens[0], &client, p.getKey)
	if token.Valid {
		req.Header.Set("CLIENTID", client.Subject)

		return true
	}
	return false

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
		return true
	}

	// Brearer
	return false
}
