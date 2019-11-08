package actors

import (
	"fmt"
	"net/http"
	"net/url"
	"soturon/client"
	"soturon/session"
)

type pep struct {
	tokenProvider *pef
	next          http.Handler
}

func (p *pep) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rctx := client.NewRContext(r.Context())
	_, ok := rctx.Token()
	if !ok {
		p.tokenProvider.authzCodeFrontChannel(w, r)
		return
	}
	p.next.ServeHTTP(w, r)
}

func (p *pep) newMUX(mux *http.ServeMux) *http.ServeMux {
	mux = p.tokenProvider.newMux(mux)
	mux.Handle("/", p)
	return mux
}

func NewPEP() *http.ServeMux {
	authURL, _ := url.Parse("http://localhost:9001/authorize")
	tokenURL, _ := url.Parse("http://localhost:9001/token")
	pep := &pep{
		tokenProvider: &pef{
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
				Scopes: []string{"ipaddress", "useragent"},
			},
			sessions: pefSessionManager{
				Manager:    session.NewManager(),
				cookieName: "policy-enforcement-front-session-id",
			},
		},
		next: &sp{},
	}
	pep.tokenProvider.next = pep
	return pep.newMUX(http.NewServeMux())
}

type sp struct{}

func (s *sp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Access Approved!!!")
	return
}
