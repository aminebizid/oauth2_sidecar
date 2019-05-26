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

// Get env var or default
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// Log the env variables required for a reverse proxy
func logSetup() {
	log.SetLevel(log.InfoLevel)
}

// Serve a reverse proxy for a given url
func serveReverseProxy(res http.ResponseWriter, req *http.Request) {
	// parse the url
	url, _ := url.Parse(targetURL)

	// create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(url)

	// Update the headers to allow for SSL redirection
	req.URL.Host = url.Host
	req.URL.Scheme = url.Scheme
	req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
	req.Host = url.Host

	// Note that ServeHttp is non blocking and uses a go routine under the hood
	proxy.ServeHTTP(res, req)
}

// Given a request send it to the appropriate url
func handleRequestAndRedirect(res http.ResponseWriter, req *http.Request) {
	if oauthProvider.Check(req) {
		serveReverseProxy(res, req)
	} else {
		http.Error(res, "Forbidden", http.StatusForbidden)
		return
	}
}

func main() {
	logSetup()
	targetURL = os.Getenv("target_url")
	port = ":" + os.Getenv("port")
	log.Infof("Server will run on: %s\n", port)
	log.Infof("Redirecting to A url: %s\n", targetURL)

	oauthProvider = oauth.NewOauthProvider(os.Getenv("well_known_url"), os.Getenv("clinet_id"), os.Getenv("redirect_uri"), os.Getenv("audience"), os.Getenv("scopes"))

	// start server
	http.HandleFunc("/", handleRequestAndRedirect)
	if err := http.ListenAndServe(port, nil); err != nil {
		panic(err)
	}
}
