package actors

import (
	"net/http"
	"soturon/authorizer"
	"soturon/client"
)

type idp struct {
	authorizer.Authenticator
}

func (i *idp) newMUX() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/authenticate", i.Authenticate)
	mux.HandleFunc("/token", i.IssueIDToken)
	mux.HandleFunc("/approve", i.LoginAndApprove)
	return mux
}

func NewIDP() *http.ServeMux {
	idp := &idp{
		Authenticator: authorizer.NewAuthenticator(map[string]*client.Config{
			"openid-rp-1": &client.Config{
				ClientID:     "openid-rp-1",
				ClientSecret: "openid-rp-secret-1",
				RedirectURL:  "http://localhost:9001/callback",
			},
		}),
	}
	return idp.newMUX()
}
