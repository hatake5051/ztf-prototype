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
	Realm string `json:"realm"`
	// Issuer は OP のドメイン
	Issuer string `json:"issuer"`
	// RP としての client credential
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	// RedirectURL は callback先のURLを表す
	RedirectURL string `json:"redirect_url"`
}

/// New は RP の設定情報をもとに OpenID RP を構築する。
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

/// RP は OpenID RP で必要な関数を定義する
type RP interface {
	/// Redirect は OpenId Provider の認証エンドポイントへリダイレクトさせる
	Redirect(w http.ResponseWriter, r *http.Request)
	/// CallbackAndExchange は OP の認可エンドポイントで認証した後
	/// コールバックしてくる先であり、IDToken を取得しにいく
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
