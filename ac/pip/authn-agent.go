package pip

import (
	"context"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// ac.AuthNAgent を実装する
type authnagent struct {
	*oidcrp
	setSubject func(session string, idtoken *oidc.IDToken) error
}

// Callback は OIDC フローでコールバックし IDToken を取得するとそれを PIP に保存する
func (a *authnagent) Callback(session string, r *http.Request) error {
	idtoken, err := a.oidcrp.CallbackAndExchange(r)
	if err != nil {
		return err
	}
	return a.setSubject(session, idtoken)
}

// OIDCRPConf は OIDC の RP としての設定情報を表す
type OIDCRPConf struct {
	// Issuer は OP のドメイン
	Issuer string
	// RP としての client credential
	ClientID     string
	ClientSecret string
	// RedirectURL は callback先のURLを表す
	RedirectURL string
}

func (conf *OIDCRPConf) new() *oidcrp {
	provider, err := oidc.NewProvider(context.Background(), conf.Issuer)
	if err != nil {
		panic(err)
	}
	oauth2Config := &oauth2.Config{
		// ここにクライアントIDとクライアントシークレットを設定
		ClientID:     conf.ClientID,
		ClientSecret: conf.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
		RedirectURL:  conf.RedirectURL,
	}
	return &oidcrp{provider, oauth2Config}
}

type oidcrp struct {
	OP   *oidc.Provider
	Conf *oauth2.Config
}

func (rp *oidcrp) Redirect(w http.ResponseWriter, r *http.Request) {
	state := "random-state" // TODO: must implement randamize
	http.Redirect(w, r, rp.Conf.AuthCodeURL(state), http.StatusFound)
}

func (rp *oidcrp) CallbackAndExchange(r *http.Request) (*oidc.IDToken, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	accessToken, err := rp.Conf.Exchange(context.Background(), r.Form.Get("code"))
	if err != nil {
		return nil, err
	}
	rawIDToken, ok := accessToken.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("missing token")
	}
	oidcConfig := &oidc.Config{
		ClientID: rp.Conf.ClientID,
	}
	verifier := rp.OP.Verifier(oidcConfig)
	return verifier.Verify(context.Background(), rawIDToken)
}
