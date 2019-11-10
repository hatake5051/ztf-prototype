package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"soturon/ctxval"
	"soturon/token"
	"soturon/util"
)

// Client は OAuth 2.0 Client を表す。
type Client interface {
	// RedirectToAuthorizer は Oauth2.0 Provider Consent Page へのリダイレクトを実行する。
	RedirectToAuthorizer(w http.ResponseWriter, r *http.Request)
	// ExchangeCodeForToken は Oauth2.0 Provider Token Endpoint からトークンを取得する。
	ExchangeCodeForToken(r *http.Request) error
	// HasToken は有効な Token を持っているかを判定する
	HasToken() bool
	// RequestWithToken は引数のリクエストヘッダに取得しておいたトークンを付与する
	SetTokenToHeader(h *http.Header)
	// Client が今持っているコンテキスト情報を返す。
	Context() context.Context
}

type client struct {
	ctx  context.Context
	conf Config
}

func (c *client) Context() context.Context {
	return c.ctx
}

func (c *client) HasToken() (ok bool) {
	_, ok = ctxval.Token(c.ctx)
	return
}

func (c *client) SetTokenToHeader(h *http.Header) {
	// 現在のリクエストスコープにアクセストークンがあるかチェック
	t, ok := ctxval.Token(c.ctx)
	if !ok {
		return
	}
	// リクエストにトークンを付与
	h.Set("Authorization", t.SetAuthorizationHeader())
}

func (c *client) RedirectToAuthorizer(w http.ResponseWriter, r *http.Request) {
	state := util.RandString(12)
	c.ctx = ctxval.WithState(c.ctx, state)
	http.Redirect(w, r, c.conf.AuthzCodeGrantURL(state), http.StatusFound)
}

func (c *client) ExchangeCodeForToken(r *http.Request) error {
	// 送られてきたリクエストの検証をし、code を取得する
	code, err := c.authzCodeGrantVerify(r)
	if err != nil {
		return err
	}
	// Oauth2.0 provider の　TokenEndpoint へのリクエストを生成して
	req, err := c.conf.TokenRequest(code)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	// レスポンスを解釈し、トークンを取得する
	token, err := c.extractTokenFrom(resp)
	if err != nil {
		return err
	}
	c.ctx = ctxval.WithToken(c.ctx, token)
	return nil
}

// authzCodeGrantVerify は rのパラメータを元に、authzCode 付与が正しく行えているか検証する
// 検証に成功すると、パラメータから authzCode を取り出し返り値とする。
func (c *client) authzCodeGrantVerify(r *http.Request) (string, error) {
	if e := r.FormValue("error"); e != "" {
		return "", errors.New(e)
	}
	// 以前生成した state とパラメータに存在する state が真に等しいか検証する。
	if state, ok := ctxval.State(c.ctx); !ok || state != r.FormValue("state") {
		return "", errors.New("bad state value")
	}
	code := r.FormValue("code")
	if code == "" {
		return "", errors.New("invalid code")
	}
	return code, nil
}

// extractTokenFrom は resp を解析し、resp.Body からアクセストークンを取得する。
func (c *client) extractTokenFrom(resp *http.Response) (*token.Token, error) {
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if status := resp.StatusCode; status < 200 || status >= 300 {
		return nil, fmt.Errorf("status code of resp from tokenEndpoint : %v", status)
	}
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	if contentType != "application/json" {
		return nil, fmt.Errorf("not supported Content-Type: %v", contentType)
	}
	t := &token.Token{}
	if err = json.Unmarshal(body, t); err != nil {
		return nil, err
	}
	return t, nil
}
