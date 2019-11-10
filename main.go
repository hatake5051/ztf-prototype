package main

import (
	"log"
	"net/http"
	"soturon/actors/cap"
	"soturon/actors/idp"
	"soturon/actors/pep"
	"soturon/client"
)

func main() {
	go func() {
		idp := idp.New(map[string]*client.Config{
			"cap-oidc-relyingparty": &client.Config{
				ClientID:     "cap-oidc-relyingparty",
				ClientSecret: "cap-oidc-relyingparty-secret",
				RedirectURL:  "http://localhost:9001/callback",
				Scopes:       []string{"openid", "foo", "bar"},
			},
		})
		mux := http.NewServeMux()
		mux.HandleFunc("/authenticate", idp.Authenticate)
		mux.HandleFunc("/token", idp.IssueIDToken)
		mux.HandleFunc("/approve", idp.LoginAndApprove)
		mux.HandleFunc("/userinfo", idp.UserInfo)
		if err := http.ListenAndServe(":9002", mux); err != nil {
			log.Fatal(err)
		}
	}()

	go func() {
		pep := pep.New(client.Config{
			ClientID:     "pep-oauth-client",
			ClientSecret: "pep-oauth-client-secret",
			RedirectURL:  "http://localhost:9000/callback",
			Endpoint: struct {
				Authz string
				Token string
			}{
				Authz: "http://localhost:9001/authorize",
				Token: "http://localhost:9001/token",
			},
			Scopes: []string{"ipaddr", "useragent"},
		}, "http://localhost:9000/", "http://localhost:9001/context")
		mux := http.NewServeMux()
		mux.Handle("/", pep)
		mux.HandleFunc("/callback", pep.Callback)
		if err := http.ListenAndServe(":9000", mux); err != nil {
			log.Fatal(err)
		}
	}()

	cap := cap.New(
		map[string]*client.Config{
			"pep-oauth-client": &client.Config{
				ClientID:     "pep-oauth-client",
				ClientSecret: "pep-oauth-client-secret",
				RedirectURL:  "http://localhost:9000/callback",
				Endpoint: struct {
					Authz string
					Token string
				}{
					Authz: "http://localhost:9001/authorize",
					Token: "http://localhost:9001/token",
				},
				Scopes: []string{"ipaddress", "useragent"},
			},
		},
		&client.Config{
			ClientID:     "cap-oidc-relyingparty",
			ClientSecret: "cap-oidc-relyingparty-secret",
			RedirectURL:  "http://localhost:9001/callback",
			Scopes:       []string{"openid", "foo", "bar"},
			Endpoint: struct {
				Authz string
				Token string
			}{Authz: "http://localhost:9002/authenticate", Token: "http://localhost:9002/token"},
		}, "http://localhost:9000/", "http://localhost:9002/userinfo")
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", cap.Authorize)
	mux.HandleFunc("/approve", cap.Approve)
	mux.HandleFunc("/token", cap.Token)
	mux.HandleFunc("/introspect", cap.IntroSpect)
	mux.HandleFunc("/callback", cap.Callback)
	mux.Handle("/context", cap)
	if err := http.ListenAndServe(":9001", mux); err != nil {
		log.Fatal(err)
	}
}
