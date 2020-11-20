package cap

import (
	"context"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type OIDCRP interface {
	Redirect(w http.ResponseWriter, r *http.Request)
	CallbackAndExchange(r *http.Request) (*oidc.IDToken, error)
}

func NewOIDCRP(issuer string,
	clientID string,
	secret string,
	redirectURL string) OIDCRP {

	provider, err := oidc.NewProvider(context.Background(), issuer)
	if err != nil {
		panic(err)
	}
	oauth2Config := &oauth2.Config{
		// ここにクライアントIDとクライアントシークレットを設定
		ClientID:     clientID,
		ClientSecret: secret,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
		RedirectURL:  redirectURL,
	}
	return &oidcrp{provider, oauth2Config}
}

type oidcrp struct {
	op   *oidc.Provider
	conf *oauth2.Config
}

func (rp *oidcrp) Redirect(w http.ResponseWriter, r *http.Request) {
	state := "" // TODO: must implement
	http.Redirect(w, r, rp.conf.AuthCodeURL(state), http.StatusFound)
}

func (rp *oidcrp) CallbackAndExchange(r *http.Request) (*oidc.IDToken, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	accessToken, err := rp.conf.Exchange(context.Background(), r.Form.Get("code"))
	if err != nil {
		return nil, err
	}
	rawIDToken, ok := accessToken.Extra("id_token").(string)
	fmt.Printf("rawIDToken is\n%s\n", rawIDToken)
	if !ok {
		return nil, fmt.Errorf("missing token")
	}
	oidcConfig := &oidc.Config{
		ClientID: rp.conf.ClientID,
	}
	verifier := rp.op.Verifier(oidcConfig)
	return verifier.Verify(context.Background(), rawIDToken)
}
