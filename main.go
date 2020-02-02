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
		// Identity Provider をサーバとして用意する
		idp := idp.New(map[string]*client.Config{
			"cap-oidc-relyingparty": &client.Config{
				ClientID:     "cap-oidc-relyingparty",
				ClientSecret: "cap-oidc-relyingparty-secret",
				RedirectURL:  "http://localhost:9001/callback",
				Scopes:       []string{"openid"},
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
		// Service Provider その１と それ用の Policy Enforcement Point の用意
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
			Scopes: []string{
				"device:useragent:raw",
				"device:useragent:predicate:havebeenused",
				"user:location:raw",
				"user:location:predicate:havebeenstayed",
				"user:location:predicate:isjapan",
			},
		}, "http://localhost:9000/",
			"http://localhost:9001/registersubsc",
			"http://localhost:9000/subscribe",
			"http://localhost:9000/",
			"http://localhost:9001/collect")
		mux := http.NewServeMux()
		mux.HandleFunc("/register", pep.RegisterSubsc)
		mux.HandleFunc("/callback", pep.Callback)
		mux.HandleFunc("/subscribe", pep.Subscribe)
		mux.HandleFunc("/updatectx", pep.UpdateCtxForm)
		if err := http.ListenAndServe(":9000", mux); err != nil {
			log.Fatal(err)
		}
	}()

	go func() {
		// Service Provider その2と それ用の Policy Enforcement Point の用意
		pep := pep.New(client.Config{
			ClientID:     "pep-oauth-client-2",
			ClientSecret: "pep-oauth-client-2-secret",
			RedirectURL:  "http://localhost:9003/callback",
			Endpoint: struct {
				Authz string
				Token string
			}{
				Authz: "http://localhost:9001/authorize",
				Token: "http://localhost:9001/token",
			},
			Scopes: []string{
				"user:location:raw",
				"user:location:predicate:isjapan",
			},
		}, "http://localhost:9003/",
			"http://localhost:9001/registersubsc",
			"http://localhost:9003/subscribe",
			"http://localhost:9003/",
			"http://localhost:9001/collect")
		mux := http.NewServeMux()
		mux.HandleFunc("/register", pep.RegisterSubsc)
		mux.HandleFunc("/callback", pep.Callback)
		mux.HandleFunc("/subscribe", pep.Subscribe)
		if err := http.ListenAndServe(":9003", mux); err != nil {
			log.Fatal(err)
		}
	}()

	// Contxt Attribute Provider の用意
	cap := cap.New(
		map[string]*client.Config{
			"pep-oauth-client": &client.Config{
				ClientID:     "pep-oauth-client",
				ClientSecret: "pep-oauth-client-secret",
				RedirectURL:  "http://localhost:9000/callback",
				Scopes: []string{
					"device:useragent:raw",
					"device:useragent:predicate:havebeenused",
					"user:location:raw",
					"user:location:predicate:havebeenstayed",
					"user:location:predicate:isjapan",
				},
			},
			"pep-oauth-client-2": &client.Config{
				ClientID:     "pep-oauth-client-2",
				ClientSecret: "pep-oauth-client-2-secret",
				RedirectURL:  "http://localhost:9003/callback",
				Scopes: []string{
					"user:location:raw",
					"user:location:predicate:isjapan",
				},
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
		},
		map[string]string{
			"pep-oauth-client":   "http://localhost:9000/",
			"pep-oauth-client-2": "http://localhost:9003/",
		},
		"http://localhost:9002/userinfo", "http://localhost:9001")
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", cap.Authorize)
	mux.HandleFunc("/approve", cap.Approve)
	mux.HandleFunc("/token", cap.Token)
	mux.HandleFunc("/introspect", cap.IntroSpect)
	mux.HandleFunc("/callback", cap.Callback)
	mux.HandleFunc("/registersubsc", cap.RegisterSubsc)
	mux.HandleFunc("/collect", cap.CollectCtx)
	mux.Handle("/register", cap)
	if err := http.ListenAndServe(":9001", mux); err != nil {
		log.Fatal(err)
	}
}
