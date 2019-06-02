package oauth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

func getWellKnown(wellKnownURL string) (wellKnown, error) {
	var wellKnown wellKnown
	resp, err := http.Get(wellKnownURL)
	if err != nil {
		return wellKnown, err
	}

	defer resp.Body.Close()
	json.NewDecoder(resp.Body).Decode(&wellKnown)
	return wellKnown, nil
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

	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have string kid")
	}

	if key := p.jwk.LookupKeyID(keyID); len(key) == 1 {
		return key[0].Materialize()
	}

	return nil, errors.New("unable to find key")
}

func (p *Provider) parseToken(token string) (bool, *jwt.StandardClaims) {
	var claims jwt.StandardClaims

	jwttoken, err := jwt.ParseWithClaims(token, &claims, p.getKey)
	if err != nil {
		return false, &claims
	}
	if jwttoken.Valid {
		return true, &claims
	}
	return false, &claims
}
