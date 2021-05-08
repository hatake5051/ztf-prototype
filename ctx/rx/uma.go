package rx

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hatake5051/ztf-prototype/ctx"
	"github.com/hatake5051/ztf-prototype/openid"
	"github.com/hatake5051/ztf-prototype/uma"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"golang.org/x/oauth2"
)

func (conf *UMAConf) new(db UMADB) (*umaClient, error) {
	// uma.Client を生成
	umaconf := uma.ClientConf{
		AuthZSrv: conf.ClientCredential.AuthZ,
		ClientCred: struct {
			ID     string
			Secret string
		}{conf.ClientCredential.ID, conf.ClientCredential.Secret},
	}
	cli := umaconf.New()

	// RPT 要求のときに使う、 Requesting Party のクレーム情報を収集
	// 今回は、 RP に対して発行された OpenID Token をクレームとして使う
	op, err := openid.NewOPFetched(conf.ReqPartyCredential.Iss)
	if err != nil {
		return nil, err
	}
	rpConf := oauth2.Config{
		ClientID:     conf.ClientCredential.ID,
		ClientSecret: conf.ClientCredential.Secret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  op.AuthorizationEndpoint,
			TokenURL: op.TokenEndpoint,
		},
		Scopes: []string{"openid"},
	}
	rqpName := conf.ReqPartyCredential.Name
	rqpPass := conf.ReqPartyCredential.Password
	tok, err := rpConf.PasswordCredentialsToken(context.Background(), rqpName, rqpPass)
	if err != nil {
		return nil, err
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("Requesting Party のIDTokenの抽出に失敗 アクセストークン: %v", tok)
	}
	jwkset, err := jwk.FetchHTTP(op.JwksURI)
	if err != nil {
		return nil, err
	}
	if _, err = jwt.ParseString(rawIDToken, jwt.WithKeySet(jwkset), jwt.WithOpenIDClaims()); err != nil {
		return nil, err
	}

	return &umaClient{rawIDToken, cli, db}, nil
}

// umaClient は caep.Receiver が add subject するときの RPT を管理する
type umaClient struct {
	rawidt string
	cli    uma.Client
	db     UMADB
}

// ExtractPermissionTicket は uma Resource server からのレスポンスから PermissionTicket を抽出しサブジェクトと紐付ける
func (u *umaClient) ExtractPermissionTicket(sub ctx.Sub, resp *http.Response) error {
	pt, err := u.cli.ExtractPermissionTicket(resp)
	if err != nil {
		return err
	}
	return u.db.SetPermissionTicket(sub, pt)
}

// RPT はサブジェクトと紐づいた Requesting Party Token を取得する
func (u *umaClient) RPT(sub ctx.Sub) (*uma.RPT, error) {
	return u.db.LoadRPT(sub)
}

// ReqRPT はサブジェクトと紐づいた PermissionTicket を使って UMA 認可プロセスを開始する
func (u *umaClient) ReqRPT(sub ctx.Sub) error {
	ticket, err := u.db.LoadPermissionTicket(sub)
	if err != nil {
		return err
	}
	tok, err := u.cli.ReqRPT(ticket, u.rawidt)
	if err != nil {
		return err
	}
	return u.db.SetRPT(sub, tok)
}
