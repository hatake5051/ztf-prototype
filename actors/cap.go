package actors

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"soturon/authorizer"
	"soturon/client"
	"soturon/session"
	"strings"
)

type cap struct {
	authorizer.Authorizer
	rp *capRP
}

func (c *cap) authnToAuthz(w http.ResponseWriter, r *http.Request) {

}

func (c *cap) protectedResource(w http.ResponseWriter, r *http.Request) {
	t := strings.Split(r.Header.Get("Authorization"), " ")
	req, err := http.NewRequest("POST", "http://localhost:9001/introspect",
		strings.NewReader(url.Values{"token": {t[1]}}.Encode()))
	if err != nil {
		fmt.Fprintf(w, "cannot create request")
		return
	}
	req.Header.Set("Content-Type",
		"application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(w, "cannot communicate with introspect endpoint")
		return
	}
	defer resp.Body.Close()
	b, _ := ioutil.ReadAll(resp.Body)
	w.Write(b)
	return
}

func (c *cap) newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", c.Authorize)
	mux.HandleFunc("/token", c.IssueToken)
	mux.HandleFunc("/approve", c.Approve)
	mux.HandleFunc("/introspect", c.IntroSpect)
	mux.HandleFunc("/resources", c.protectedResource)
	mux.HandleFunc("/authenticate", c.rp.authnCodeFrontChannel)
	mux.HandleFunc("/callback", c.rp.authnCodeBackChannel)
	return mux
}

func NewCAP() *http.ServeMux {
	authURL, _ := url.Parse("http://localhost:9002/authenticate")
	tokenURL, _ := url.Parse("http://localhost:9002/token")
	cap := &cap{
		Authorizer: authorizer.New(map[string]*client.Config{
			"oauth-client-1": &client.Config{
				ClientID:     "oauth-client-1",
				ClientSecret: "oauth-client-secret-1",
				RedirectURL:  "http://localhost:9000/callback",
			}},
		),
		rp: &capRP{
			conf: client.Config{
				ClientID:     "openid-rp-1",
				ClientSecret: "openid-rp-secret-1",
				RedirectURL:  "http://localhost:9001/callback",
				Endpoint: struct {
					Authz *url.URL
					Token *url.URL
				}{
					Authz: authURL,
					Token: tokenURL,
				},
				Scopes: []string{"foo", "bar", "openid"},
			},
			sessions: capSessionManager{
				Manager:    session.NewManager(),
				cookieName: "context-attributeprovider-front-session-id",
			},
		},
	}
	return cap.newMux()
}

type capRP struct {
	conf     client.Config
	sessions capSessionManager
}

func (c *capRP) authnCodeFrontChannel(w http.ResponseWriter, r *http.Request) {
	rp := c.conf.RP(client.NewRContext(r.Context()))
	sessionID := c.sessions.UniqueID()
	c.sessions.setRP(sessionID, rp)
	http.SetCookie(w, &http.Cookie{Name: c.sessions.cookieName, Value: sessionID})
	rp.RedirectToAuthenticator(w, r)
}
func (c *capRP) authnCodeBackChannel(w http.ResponseWriter, r *http.Request) {
	rp, ok := c.sessions.extractRPFromCookie(r)
	if !ok {
		w.WriteHeader(400)
		fmt.Fprintf(w, "invalid sessionID in the cookie")
		return
	}
	if err := rp.ExchangeCodeForIDToken(w, r); err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "%v", err)
		return
	}
	fmt.Fprint(w, "authentication completed!!!")
}

type capSessionManager struct {
	session.Manager
	cookieName string
}

func (cap *capSessionManager) setRP(sID string, r client.RP) {
	cap.Manager.Set(sID, "rp", r)
}

func (cap *capSessionManager) extractRP(sID string) (client.RP, bool) {
	s, ok := cap.Manager.Find(sID)
	if !ok {
		return nil, false
	}
	i, ok := s.Find("rp")
	r, ok := i.(client.RP)
	return r, ok
}

func (cap *capSessionManager) extractRPFromCookie(r *http.Request) (client.RP, bool) {
	cookie, err := r.Cookie(cap.cookieName)
	if err != nil {
		return nil, false
	}
	return cap.extractRP(cookie.Value)
}
