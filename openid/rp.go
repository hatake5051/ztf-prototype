package openid

import (
	"context"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/lestrrat-go/jwx/jwt/openid"
	"golang.org/x/oauth2"
)

// Conf は OpenID Connect の RP としての設定情報を表す
type Conf struct {
	// Issuer は OP のドメイン
	Issuer string
	// RP としての client credential
	ClientID     string
	ClientSecret string
	// RedirectURL は callback先のURLを表す
	RedirectURL string
}

func (c *Conf) New() RP {
	op, err := NewOPFetched(c.Issuer)
	if err != nil {
		panic(fmt.Errorf("OP(%s)の設定取得に失敗 %v", c.Issuer, err))
	}
	conf := &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  op.AuthorizationEndpoint,
			TokenURL: op.TokenEndpoint,
		},
		Scopes:      []string{"openid"},
		RedirectURL: c.RedirectURL,
	}
	return &rp{
		op:   op,
		conf: conf,
	}
}

type RP interface {
	Redirect(w http.ResponseWriter, r *http.Request)
	CallbackAndExchange(r *http.Request) (openid.Token, error)
}

type rp struct {
	op   *OP
	conf *oauth2.Config
}

func (rp *rp) Redirect(w http.ResponseWriter, r *http.Request) {
	state := "" // TODO: must implement
	http.Redirect(w, r, rp.conf.AuthCodeURL(state), http.StatusFound)
}

func (rp *rp) CallbackAndExchange(r *http.Request) (openid.Token, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	accessToken, err := rp.conf.Exchange(context.Background(), r.Form.Get("code"))
	if err != nil {
		return nil, err
	}
	rawIDToken, ok := accessToken.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("missing token")
	}
	jwkset, err := jwk.FetchHTTP(rp.op.JwksURI)
	if err != nil {
		return nil, err
	}
	tok, err := jwt.ParseString(rawIDToken, jwt.WithKeySet(jwkset), jwt.WithOpenIDClaims())
	if err != nil {
		return nil, err
	}
	return tok.(openid.Token), nil
}
