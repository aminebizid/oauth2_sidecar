package oauth

import (
	"net/http"

	log "github.com/Sirupsen/logrus"
)

// SetSession stores Cookie session
func (p *Provider) SetSession(w http.ResponseWriter, r *http.Request, key string, value interface{}) {
	session, _ := p.store.Get(r, p.cookieName)
	session.Values[key] = value
	session.Save(r, w)
}

// GetSession Get cookie value
func (p *Provider) GetSession(r *http.Request, key string) interface{} {
	session, err := p.store.Get(r, p.cookieName)
	if err != nil {
		log.Debugf("Unable to get store %s", p.cookieName)
		return nil
	}
	if v, ok := session.Values[key]; ok {
		return v
	}
	log.Debugf("Session Key not found %s", key)
	return nil
}

// GetSessionString Get cookie value in string format
func (p *Provider) GetSessionString(r *http.Request, key string) string {
	session, err := p.store.Get(r, p.cookieName)
	if err != nil {
		log.Debugf("Unable to store %s", p.cookieName)
		return ""
	}
	if v, ok := session.Values[key]; ok {
		return v.(string)
	}
	return ""
}
