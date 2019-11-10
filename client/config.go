package client

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// Config は Oauth2.0 Client の設定情報を表す。
type Config struct {
	// OAuth2.0 AuthServer に登録したID
	ClientID string
	// OAuth2.0 AuthServer に登録した際のパスワード
	ClientSecret string
	// AuthzCode を持ったリクエストのリダイレクト先
	RedirectURL string
	// Access Token 取得の際に要求する権限スコープ
	Scopes []string
	// Oauth2.0 Provider のエンドポイント
	Endpoint struct {
		Authz string
		Token string
	}
}

// AuthzCodeGrantURL は Oauth2.0 Provider の Consent Page へのリダイレクトURLを返す。
func (c *Config) AuthzCodeGrantURL(state string) string {
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {c.ClientID},
		"redirect_uri":  {c.RedirectURL},
		"state":         {state},
		"scope":         {strings.Join(c.Scopes, " ")},
	}
	authz, err := url.Parse(c.Endpoint.Authz)
	if err != nil {
		return ""
	}
	authorizeURL := url.URL{
		Scheme:   "http",
		Host:     authz.Host,
		Path:     authz.Path,
		RawQuery: v.Encode(),
	}
	return authorizeURL.String()
}

// TokenRequest は取得した code を元に Oauth2.0 Provider TokenEndpoint へのリクエストを生成する。
func (c *Config) TokenRequest(code string) (*http.Request, error) {
	v := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {c.RedirectURL},
	}
	req, err := http.NewRequest("POST", c.Endpoint.Token, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type",
		"application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(c.ClientID),
		url.QueryEscape(c.ClientSecret))
	return req, nil
}

// Client は Config情報を元にした OAuth2.0 Client を生成する
func (c Config) Client(ctx context.Context) Client {
	return &client{
		ctx:  ctx,
		conf: c,
	}
}

// RP は Config情報を元にした OIDC RP を生成する
func (c Config) RP(ctx context.Context) RP {
	return &client{
		ctx:  ctx,
		conf: c,
	}
}
