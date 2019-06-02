package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/aminebizid/oauth2_sidecar/pkg/oauth"
)

var (
	targetURL     string
	port          string
	oauthProvider *oauth.Provider
)

// getEnv env var or default
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getEnvOrPanic(key string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	panic("ENV not found :" + key)
}

// Log the env variables required for a reverse proxy
func logSetup() {
	logLevel := getEnv("logLevel", "info")
	parsedLogLevel, err := log.ParseLevel(logLevel)
	if err == nil {
		log.SetLevel(parsedLogLevel)
		log.Infof("Log level set to: %s", parsedLogLevel)
	} else {
		log.Errorf("Invalid value for --log-level: %s. Setting level to 'Info'", logLevel)
		log.SetLevel(log.InfoLevel)
	}

	log.SetLevel(log.DebugLevel)
}

// Serve a reverse proxy for a given url
func serveReverseProxy(w http.ResponseWriter, r *http.Request, client string) {
	// parse the url
	url, _ := url.Parse(targetURL)

	// create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(url)

	// Update the headers to allow for SSL redirection
	r.URL.Host = url.Host
	r.URL.Scheme = url.Scheme
	r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
	r.Header.Set("CLIENTID", client)
	r.Host = url.Host
	log.Debug("Running proxy")
	// Note that ServeHttp is non blocking and uses a go routine under the hood
	proxy.ServeHTTP(w, r)
}

// Given a request send it to the appropriate url
func handleRequestAndRedirect(w http.ResponseWriter, r *http.Request) {
	log.Debug("GET " + r.Host + r.URL.Path)
	log.Debug(oauthProvider.GetSession(r, "origin_request"))
	ok, client := oauthProvider.Check(w, r)
	if ok {
		serveReverseProxy(w, r, client.Subject)
	}
}

func main() {
	logSetup()
	targetURL = getEnvOrPanic("target_url")
	port = ":" + getEnv("port", "5000")
	wellKnownURL := getEnvOrPanic("well_known_url")
	clientID := getEnvOrPanic("client_id")
	redirectURI := getEnvOrPanic("redirect_uri")
	audience := getEnvOrPanic("audience")
	scopes := getEnv("scopes", "")
	sessionKey := getEnv("session_key", "super-secret-key")

	log.Infof("Well Known URL: %s\n", wellKnownURL)
	log.Infof("Client ID: %s\n", clientID)
	log.Infof("Redirect URI: %s\n", redirectURI)
	log.Infof("Audience: %s\n", audience)
	log.Infof("Scopes: %s\n", scopes)
	log.Infof("Session Key: %s\n", sessionKey)
	log.Infof("Server will run on: %s\n", port)
	log.Infof("Redirecting to A url: %s\n", targetURL)

	oauthProvider = oauth.NewOauthProvider(
		wellKnownURL,
		clientID,
		redirectURI,
		audience,
		scopes,
		sessionKey)

	// start server
	http.HandleFunc("/", handleRequestAndRedirect)
	if err := http.ListenAndServe(port, nil); err != nil {
		panic(err)
	}
}
