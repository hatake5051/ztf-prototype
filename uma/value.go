package uma

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

// Res は
type Res struct {
	ID                 string   `json:"_id,omitempty"`
	Name               string   `json:"name,omitempty"`
	Owner              string   `json:"owner,omitempty"`
	OwnerManagedAccess bool     `json:"ownerManagedAccess,omitempty"`
	Scopes             []string `json:"scopes,omitempty"`
}

// ResReqForPT は
type ResReqForPT struct {
	ID     string   `json:"resource_id"`
	Scopes []string `json:"resource_scopes"`
}

// PermissionTicket は認可サーバが発行した許可チケットを表す
type PermissionTicket struct {
	// 許可チケットを表す文字列
	Ticket string
	// 401 WWW-Authenticate で許可チケットを取得した場合の補足情報
	// nullable
	InitialOption *struct {
		AuthZSrv string
		ResSrv   string
	}
}

// RPT は Requesting Party Token を表し oauth2.Token のこと
type RPT struct {
	oauth2.Token
}

// SetAuthHeader はRPTをHTTPリクエストのヘッダーにセットする
func (t *RPT) SetAuthHeader(r *http.Request) {
	r.Header.Set("Authorization", t.Type()+" "+t.AccessToken)
}

// AuthZSrv は UMA-enabled な認可サーバのエンドポイントなどを表す
type AuthZSrv struct {
	Issuer        string
	TokenURL      string
	RRegURL       string
	PermissionURL string
}

// umaJSON は UMA-enabled AuthZSrv の Well-known 設定情報
type umaJSON struct {
	Issuer        string `json:"issuer"`
	TokenURL      string `json:"token_endpoint"`
	RRegURL       string `json:"resource_registration_endpoint"`
	PermissionURL string `json:"permission_endpoint"`
}

// NewAuthZSrv は issuer の well-known エンドポイントにアクセスして認可サーバの情報を取得する
func NewAuthZSrv(issuer string) (*AuthZSrv, error) {
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/uma2-configuration"
	resp, err := http.Get(wellKnown)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("statuscode: %s", resp.Status)
	}
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	if contentType != "application/json" {
		return nil, fmt.Errorf("contentType(%v) is not app/json", contentType)
	}
	u := new(umaJSON)
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(u); err != nil {
		return nil, err
	}
	if u.Issuer != issuer {
		return nil, fmt.Errorf("oidc: issuer did not match the issuer returned by provider, expected %q got %q", issuer, u.Issuer)
	}

	return &AuthZSrv{
		Issuer:        u.Issuer,
		TokenURL:      u.TokenURL,
		RRegURL:       u.RRegURL,
		PermissionURL: u.PermissionURL,
	}, nil
}
