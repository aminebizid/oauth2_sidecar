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
	log.SetLevel(log.DebugLevel)
}

// Serve a reverse proxy for a given url
func serveReverseProxy(w http.ResponseWriter, r *http.Request) {
	// parse the url
	url, _ := url.Parse(targetURL)
	// if url.Path == "/favicon.ico" {
	// 	w.Write([]byte(""))
	// 	return
	// }

	// create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(url)

	// Update the headers to allow for SSL redirection
	r.URL.Host = url.Host
	r.URL.Scheme = url.Scheme
	r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
	log.Debug(oauthProvider.GetSession(r, "CLIENTID"))
	r.Header.Set("CLIENTID", oauthProvider.GetSession(r, "CLIENTID").(string))
	r.Host = url.Host
	log.Debug("Running proxy")
	// Note that ServeHttp is non blocking and uses a go routine under the hood
	proxy.ServeHTTP(w, r)
}

// Given a request send it to the appropriate url
func handleRequestAndRedirect(w http.ResponseWriter, r *http.Request) {
	log.Debug("GET " + r.Host + r.URL.Path)
	log.Debug(oauthProvider.GetSession(r, "origin_request"))
	if oauthProvider.Check(w, r) {
		serveReverseProxy(w, r)
	}
}

func main() {
	logSetup()
	targetURL = os.Getenv("target_url")
	port = ":" + os.Getenv("port")
	log.Infof("Server will run on: %s\n", port)
	log.Infof("Redirecting to A url: %s\n", targetURL)

	oauthProvider = oauth.NewOauthProvider(os.Getenv("well_known_url"), os.Getenv("client_id"), os.Getenv("redirect_uri"), os.Getenv("audience"), os.Getenv("scopes"))

	// start server
	http.HandleFunc("/", handleRequestAndRedirect)
	if err := http.ListenAndServe(port, nil); err != nil {
		panic(err)
	}
}
