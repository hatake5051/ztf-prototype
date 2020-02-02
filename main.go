package main

import (
	"log"
	"net/http"
	"os"
	"soturon/actors/cap"
	"soturon/actors/idp"
	"soturon/actors/pep"
	"soturon/client"
)

func main() {
	idpConf := &idp.Conf{Addr: os.Getenv("IDP_ADDRESS")}
	capConf := &cap.Conf{os.Getenv("CAP_ADDRESS")}
	rp1Conf := &pep.Conf{os.Getenv("RP1_ADDRESS")}
	rp2Conf := &pep.Conf{os.Getenv("RP2_ADDRESS")}
	go func() {
		// Identity Provider をサーバとして用意する
		idp := idp.New(
			idpConf.Addr,
			map[string]*client.Config{
				"cap-oidc-relyingparty": &client.Config{
					ClientID:     "cap-oidc-relyingparty",
					ClientSecret: "cap-oidc-relyingparty-secret",
					RedirectURL:  capConf.CallbackEndpoint(),
					Scopes:       []string{"openid"},
				},
			})
		mux := http.NewServeMux()
		mux.HandleFunc("/authenticate", idp.Authenticate)
		mux.HandleFunc("/token", idp.IssueIDToken)
		mux.HandleFunc("/approve", idp.LoginAndApprove)
		mux.HandleFunc("/userinfo", idp.UserInfo)
		if err := http.ListenAndServe(idpConf.Addr, mux); err != nil {
			log.Fatal(err)
		}
	}()

	go func() {
		// Service Provider その１と それ用の Policy Enforcement Point の用意
		pep := pep.New(client.Config{
			ClientID:     "pep-oauth-client",
			ClientSecret: "pep-oauth-client-secret",
			RedirectURL:  rp1Conf.CallbackEndponit(),
			Endpoint: struct {
				Authz string
				Token string
			}{
				capConf.AuthorizeEndponit(),
				capConf.TokenEndponit(),
			},
			Scopes: []string{
				"device:useragent:raw",
				"device:useragent:predicate:recentlyused",
				"user:location:raw",
				"user:location:predicate:recentlystayed",
				"user:location:predicate:isjapan",
			},
		},
			"http://"+rp1Conf.Addr+"/",
			capConf.RegistersubscEndponit(),
			rp1Conf.SubscribeEndponit(),
			"http://"+rp1Conf.Addr+"/",
			capConf.CollectEndponit())
		mux := http.NewServeMux()
		mux.Handle("/", pep)
		mux.HandleFunc("/register", pep.RegisterSubsc)
		mux.HandleFunc("/callback", pep.Callback)
		mux.HandleFunc("/subscribe", pep.Subscribe)
		mux.HandleFunc("/updatectx", pep.UpdateCtxForm)
		mux.HandleFunc("/approve", pep.Approve)
		if err := http.ListenAndServe(rp1Conf.Addr, mux); err != nil {
			log.Fatal(err)
		}
	}()

	go func() {
		// Service Provider その2と それ用の Policy Enforcement Point の用意
		pep := pep.New(client.Config{
			ClientID:     "pep-oauth-client-2",
			ClientSecret: "pep-oauth-client-2-secret",
			RedirectURL:  rp2Conf.CallbackEndponit(),
			Endpoint: struct {
				Authz string
				Token string
			}{
				capConf.AuthorizeEndponit(),
				capConf.TokenEndponit(),
			},
			Scopes: []string{
				"user:location:raw",
				"user:location:predicate:isjapan",
			},
		},
			"http://"+rp2Conf.Addr+"/",
			capConf.RegistersubscEndponit(),
			rp2Conf.SubscribeEndponit(),
			"http://"+rp2Conf.Addr+"/",
			capConf.CollectEndponit())
		mux := http.NewServeMux()
		mux.Handle("/", pep)
		mux.HandleFunc("/register", pep.RegisterSubsc)
		mux.HandleFunc("/callback", pep.Callback)
		mux.HandleFunc("/subscribe", pep.Subscribe)
		mux.HandleFunc("/updatectx", pep.UpdateCtxForm)
		mux.HandleFunc("/approve", pep.Approve)
		if err := http.ListenAndServe(rp2Conf.Addr, mux); err != nil {
			log.Fatal(err)
		}
	}()

	// Contxt Attribute Provider の用意
	cap := cap.New(
		map[string]*client.Config{
			"pep-oauth-client": &client.Config{
				ClientID:     "pep-oauth-client",
				ClientSecret: "pep-oauth-client-secret",
				RedirectURL:  rp1Conf.CallbackEndponit(),
				Scopes: []string{
					"device:useragent:raw",
					"device:useragent:predicate:recentlyused",
					"user:location:raw",
					"user:location:predicate:recentlystayed",
					"user:location:predicate:isjapan",
				},
			},
			"pep-oauth-client-2": &client.Config{
				ClientID:     "pep-oauth-client-2",
				ClientSecret: "pep-oauth-client-2-secret",
				RedirectURL:  rp2Conf.CallbackEndponit(),
				Scopes: []string{
					"user:location:raw",
					"user:location:predicate:isjapan",
				},
			},
		},
		&client.Config{
			ClientID:     "cap-oidc-relyingparty",
			ClientSecret: "cap-oidc-relyingparty-secret",
			RedirectURL:  capConf.CallbackEndpoint(),
			Scopes:       []string{"openid"},
			Endpoint: struct {
				Authz string
				Token string
			}{
				idpConf.AuthenticateEndpint(),
				idpConf.TokenEndpint(),
			},
		},
		map[string]string{
			"pep-oauth-client":   "http://" + rp1Conf.Addr + "/",
			"pep-oauth-client-2": "http://" + rp2Conf.Addr + "/",
		},
		idpConf.UserInfoEndpoint(),
		"http://"+capConf.Addr)
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", cap.Authorize)
	mux.HandleFunc("/approve", cap.Approve)
	mux.HandleFunc("/token", cap.Token)
	mux.HandleFunc("/introspect", cap.IntroSpect)
	mux.HandleFunc("/callback", cap.Callback)
	mux.HandleFunc("/registersubsc", cap.RegisterSubsc)
	mux.HandleFunc("/collect", cap.CollectCtx)
	mux.Handle("/register", cap)
	if err := http.ListenAndServe(capConf.Addr, mux); err != nil {
		log.Fatal(err)
	}
}
