package uma

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/lestrrat-go/jwx/jwt"
	"golang.org/x/oauth2"
)

// SubAtAuthZ は認可サーバにおけるユーザを表現する。
type SubAtAuthZ string

// SubAtResSrv はユーザの識別子
// リソースサーバ がこの識別子を理解できる
type SubAtResSrv string

// ResID はリソース識別子
// 認可サーバが識別子を発行し、リソースサーバ が Permission Ticket 発行時に使用する
type ResID string

// ResType はリソースのタイプを表す
// リソースサーバ が設定する
type ResType string

// Res は認可サーバが保護するリソースサーバ上のリソースを表す
type Res struct {
	// ID はリソースの識別子であり、認可サーバが管理している
	ID ResID `json:"_id,omitempty"`
	// Type は the sementics of the resource を表す
	Type ResType `json:"type,omitempty"`
	// Name はリソースの human-readable string
	Name string `json:"name,omitempty"`
	// リソースに対する利用可能なスコープリスト
	Scopes []string `json:"scopes,omitempty"`
	// Owner はこのリソースのオーナを示す
	// KeyCloak の独自設定である。 PAT の Subject がデフォルト
	Owner SubAtAuthZ `json:"owner,omitempty"`
	// OwnerManagedAccess は true のとき、このリソースを Owner が管理できることを表す
	// KeyCloak の独自設定であり、 UMA でリソース管理する時は true にする
	OwnerManagedAccess bool `json:"ownerManagedAccess,omitempty"`
}

// ResReqForPT は リソースを要求する時のリクエストを表す
type ResReqForPT struct {
	ID     ResID    `json:"resource_id"`
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

// NewPermissionTicket は許可チケットを構築する
func NewPermissionTicket(ticket, authZSrv, resSrv string) *PermissionTicket {
	return &PermissionTicket{
		Ticket: ticket,
		InitialOption: &struct {
			AuthZSrv string
			ResSrv   string
		}{authZSrv, resSrv},
	}
}

// PAT は Protection API Token を表し oauth2.Token のこと
type PAT struct {
	t *oauth2.Token
	e time.Time // refresh token's expiration time
}

func (t *PAT) new(tt *oauth2.Token) {
	t = new(PAT)
	t.t = tt
	if refreshExpiresIn, ok := tt.Extra("refresh_expires_in").(int); ok {
		t.e = time.Now().Add(time.Duration(refreshExpiresIn) * time.Second)
	}
}

func (t *PAT) refreshExpired() bool {
	// t.e が 0 の場合は refresh の締め切りはないと考える
	if t.e.IsZero() {
		return false
	}
	return t.e.Round(0).Add(-10 * time.Second).Before(time.Now())
}

// Keycloak では登録済みのリソース一覧を ProtectionAPI を介して行うと、
// PAT 発行したユーザ以外のそのリソースサーバで登録済みの全てのリソースが返ってくる
// PAT 発行したユーザだけのリソースが欲しいので PAT を解釈している
func (t *PAT) subject() (SubAtAuthZ, error) {
	tok, err := jwt.ParseString(t.t.AccessToken)
	if err != nil {
		return "", fmt.Errorf("Cannot extract subject from PAT %v", err)
	}
	return SubAtAuthZ(tok.Subject()), nil
}

// RPT は Requesting Party Token を表し oauth2.Token のこと
type RPT struct {
	t *oauth2.Token
	e time.Time // refresh token's expiration time
}

func (t *RPT) new(tt *oauth2.Token) {
	t = new(RPT)
	t.t = tt
	if refreshExpiresIn, ok := tt.Extra("refresh_expires_in").(int); ok {
		t.e = time.Now().Add(time.Duration(refreshExpiresIn) * time.Second)
	}
}

func (t *RPT) refreshExpired() bool {
	// t.e が 0 の場合は refresh の締め切りはないと考える
	if t.e.IsZero() {
		return false
	}
	return t.e.Round(0).Add(-10 * time.Second).Before(time.Now())
}

// AuthZSrv は UMA-enabled な認可サーバのエンドポイントなどを表す
type AuthZSrvConf struct {
	Issuer        string `json:"issuer"`
	AuthZURL      string `json:"authorization_endpoint"`
	TokenURL      string `json:"token_endpoint"`
	RRegURL       string `json:"resource_registration_endpoint"`
	PermissionURL string `json:"permission_endpoint"`
}

// NewAuthZSrv は issuer の well-known エンドポイントにアクセスして認可サーバの情報を取得する
func NewAuthZSrvConf(issuer *url.URL) (*AuthZSrvConf, error) {
	ur := *issuer
	// Keycloak の場合
	ur.Path = path.Join(ur.Path, "/.well-known/uma2-configuration")
	resp, err := http.Get(ur.String())
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
	a := new(AuthZSrvConf)
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(a); err != nil {
		return nil, err
	}
	if a.Issuer != issuer.String() {
		return nil, fmt.Errorf("authZ issuer unmatched, expected %q got %q", issuer, a.Issuer)
	}
	return a, nil
}
