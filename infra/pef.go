package infra

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"soturon/client"
	"soturon/session"
)

type pef struct {
	conf     client.Config
	sessions pefSessionManager
}

func (p *pef) index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`
	<html><head/><body>
		<a href="http://localhost:9000/authorize">authorize</a>
	</body></html>
	`))
}

func (p *pef) authzCodeFrontChannel(w http.ResponseWriter, r *http.Request) {
	c := p.conf.Client(client.NewRContext(r.Context()))
	sessionID := p.sessions.UniqueID()
	p.sessions.setClient(sessionID, c)
	http.SetCookie(w, &http.Cookie{Name: p.sessions.cookieName, Value: sessionID})
	c.RedirectToAuthorizer(w, r)
}

func (p *pef) authzCodeBackChannel(w http.ResponseWriter, r *http.Request) {
	c, ok := p.sessions.extractClientFromCookie(r)
	if !ok {
		w.WriteHeader(400)
		fmt.Fprintf(w, "invalid sessionID in the cookie")
		return
	}
	if err := c.ExchangeCodeForToken(w, r); err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "%v", err)
		return
	}
	fmt.Fprint(w, `<html><head/><body>
	この後は context-aware アクセス管理を行う。一時的にリターン<br>
	<a href="/fetch">コンテキストの取得</a>
	</body></html>`)
}

func (p *pef) fetchContext(w http.ResponseWriter, r *http.Request) {
	c, ok := p.sessions.extractClientFromCookie(r)
	if !ok {
		w.WriteHeader(400)
		fmt.Fprintf(w, "invalid sessionID in the cookie")
		return
	}
	req, ok := c.RequestWithToken("GET", "http://localhost:9001/resources")
	if !ok {
		w.WriteHeader(400)
		fmt.Fprintf(w, "invalid sessionID in the cookie")
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	b, _ := ioutil.ReadAll(resp.Body)
	w.Write(b)
}

func (p *pef) newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", p.index)
	mux.HandleFunc("/authorize", p.authzCodeFrontChannel)
	mux.HandleFunc("/callback", p.authzCodeBackChannel)
	mux.HandleFunc("/fetch", p.fetchContext)
	return mux
}

func NewPEF() *http.ServeMux {
	authURL, _ := url.Parse("http://localhost:9001/authorize")
	tokenURL, _ := url.Parse("http://localhost:9001/token")
	pef := &pef{
		conf: client.Config{
			ClientID:     "oauth-client-1",
			ClientSecret: "oauth-client-secret-1",
			RedirectURL:  "http://localhost:9000/callback",
			Endpoint: struct {
				Authz *url.URL
				Token *url.URL
			}{
				Authz: authURL,
				Token: tokenURL,
			},
			Scopes: []string{"foo", "bar"},
		},
		sessions: pefSessionManager{
			Manager:    session.NewManager(),
			cookieName: "policy-enforcement-front-session-id",
		},
	}
	return pef.newMux()
}

type pefSessionManager struct {
	session.Manager
	cookieName string
}

func (psm *pefSessionManager) setClient(sID string, c client.Client) {
	psm.Manager.Set(sID, "client", c)
}

func (psm *pefSessionManager) extractClient(sID string) (client.Client, bool) {
	s, ok := psm.Manager.Find(sID)
	if !ok {
		return nil, false
	}
	i, ok := s.Find("client")
	c, ok := i.(client.Client)
	return c, ok
}

func (psm *pefSessionManager) extractClientFromCookie(r *http.Request) (client.Client, bool) {
	cookie, err := r.Cookie(psm.cookieName)
	if err != nil {
		return nil, false
	}
	return psm.extractClient(cookie.Value)

}
