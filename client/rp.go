package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"soturon/ctxval"
	"soturon/token"
)

// RP は OIDC RP を表す。
type RP interface {
	// RedirectToAuthenticator は OID Provider AuthzEndpoint へのリダイレクトを実行する。
	RedirectToAuthenticator(w http.ResponseWriter, r *http.Request)
	// ExchangeCodeForIDToken は OID Provider TokenEndpoint からIDトークンを取得する。
	ExchangeCodeForIDToken(r *http.Request) error
	// HasIDToken は有効な IDToken を持っているか判定する
	HasIDToken() bool
	// SetIDTokenToHeader は引数のリクエストヘッダに取得しておいたIDトークンを付与する
	SetIDTokenToHeader(h *http.Header)
	// RP が今持っているコンテキスト情報を返す。
	Context() context.Context
}

func (rp *client) HasIDToken() bool {
	_, ok := ctxval.IDToken(rp.ctx)
	return ok
}

func (rp *client) SetIDTokenToHeader(h *http.Header) {
	idt, ok := ctxval.IDToken(rp.ctx)
	if !ok {
		return
	}
	h.Set("Authorization", idt.SetAuthorizationHeader())
}

func (rp *client) RedirectToAuthenticator(w http.ResponseWriter, r *http.Request) {
	rp.RedirectToAuthorizer(w, r)
}

func (rp *client) ExchangeCodeForIDToken(r *http.Request) error {
	code, err := rp.authzCodeGrantVerify(r)
	if err != nil {
		return err
	}
	req, err := rp.conf.TokenRequest(code)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	t, err := rp.extractTokenWithIDFrom(resp)
	if err != nil {
		return err
	}
	// IDToken のJWTを検証する
	if err := t.ParseIDToken(); err != nil {
		return err
	}
	rp.ctx = ctxval.WithIDToken(rp.ctx, t)
	return nil
}

func (rp *client) extractTokenWithIDFrom(resp *http.Response) (*token.IDToken, error) {
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if status := resp.StatusCode; status < 200 || status >= 300 {
		return nil,
			fmt.Errorf("status code of resp from tokenEndpoint : %v", status)
	}
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	if contentType != "application/json" {
		return nil, fmt.Errorf("not supported Content-Type: %v", contentType)
	}
	t := &token.IDToken{}
	if err = json.Unmarshal(body, t); err != nil {
		return nil, err
	}
	return t, nil
}
