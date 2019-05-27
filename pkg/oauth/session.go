package oauth

import "net/http"

// SetSession stores Cookie session
func (p *Provider) SetSession(w http.ResponseWriter, r *http.Request, key string, value interface{}) {
	session, _ := p.store.Get(r, p.cookieName)
	session.Values[key] = value
	session.Save(r, w)
}

// GetSession Get cookie value
func (p *Provider) GetSession(r *http.Request, key string) interface{} {
	session, _ := p.store.Get(r, p.cookieName)
	if v, ok := session.Values[key]; ok {
		return v
	}
	return nil
}
