package uma

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// ResSrvConf は UMA-enabled なリソースサーバの設定情報
type ResSrvConf struct {
	// AuthZSrv は認可サーバの URL である
	AuthZSrv string
	// PATClient は Protection API Token を取得するためのクライアント情報
	PATClient struct {
		ID          string
		Secret      string
		RedirectURL string
	}
}

// New は設定情報から ResSrv を構成する
// UMAAuthZSrv の設定に失敗するとパニック
func (c *ResSrvConf) New(db ResSrvDB) ResSrv {
	authZSrv, err := NewAuthZSrv(c.AuthZSrv)
	if err != nil {
		panic(fmt.Sprintf("ResSrv の構成に失敗(UMA認可サーバの設定を取得できなかった) err:%v", err))
	}

	// 認可サーバに対して PAT を要求する時に使用する OAuth2.0 Client 設定情報
	conf := &oauth2.Config{
		ClientID:     c.PATClient.ID,
		ClientSecret: c.PATClient.Secret,
		RedirectURL:  c.PATClient.RedirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authZSrv.AuthZURL,
			TokenURL: authZSrv.TokenURL,
		},
	}

	return &ressrv{
		authZ: authZSrv,
		pat:   &patManager{conf, db},
	}
}

// ResSrvDB は リソースサーバで使用するデータの保存先
// PAT をサブジェクトに紐づけて保存し、読み出すことができる
// PAT を取得するときに使う state を管理できる
type ResSrvDB interface {
	LoadPAT(SubAtResSrv) (*PAT, error)
	SavePAT(SubAtResSrv, *PAT) error
	LoadPATOfResSrv() (*PAT, error)
	SavePATOfResSrv(*PAT) error
	SaveOAuthState(state string, sub SubAtResSrv) error
	LoadAndDeleteOAuthState(state string) (SubAtResSrv, error)
}

// ResSrv は UMA-enabled なリソースサーバを表す
type ResSrv interface {
	//CallbackForPAT は PAT 取得フローのリダイレクトバックを処理する
	CallbackForPAT(SubAtResSrv, *http.Request) error
	// CRUD は method に基づいて res を Restful に操作する
	CRUD(ownerID SubAtResSrv, method string, res *Res) (*Res, error)
	// List は owner が UMA AuthZSrv に登録したコンテキストを一覧する
	List(SubAtResSrv) (resIDList []string, err error)
	// PermissionTicket は reses にアクセスを求めている情報をまとめて Permission Ticket に変換する
	PermissionTicket(reses []ResReqForPT) (*PermissionTicket, error)
}

// patManager はユーザが ResSrv に発行した PAT を管理する
type patManager struct {
	// conf は PAT 取得に際の OAuth2.0 Client 設定情報
	conf *oauth2.Config
	// db は PAT を管理するDB
	db ResSrvDB
}

// patForResSrv はリソースサーバ のサービスアカウントを使って PAT を取得する
// 内部では Client Credentials Flow を使って PAT を認可サーバから取得する
func (m *patManager) patForResSrv() (*PAT, error) {
	// すでに保存してあればそれを返す
	if pat, err := m.db.LoadPATOfResSrv(); err == nil {
		return pat, nil
	}
	// 一度も取得してない時は、認可サーバから取得しにいく
	clientCredConf := &clientcredentials.Config{
		ClientID:     m.conf.ClientID,
		ClientSecret: m.conf.ClientSecret,
		TokenURL:     m.conf.Endpoint.TokenURL,
	}
	tok, err := clientCredConf.Token(context.Background())
	if err != nil {
		return nil, &ProtectionAPIError{
			Code:        ProtectionAPICodeUnAuthorized,
			Description: err.Error(),
		}
	}
	pat := &PAT{*tok}
	if err := m.db.SavePATOfResSrv(pat); err != nil {
		return nil, err
	}

	return pat, nil
}

// pat は ownerID がリソースサーバ に発行した PAT を取得する
// まだ持っていない場合は、 ProtectionAPICodeUnAuthorized でエラーを返す
func (m *patManager) pat(ownerID SubAtResSrv) (*PAT, error) {
	if pat, err := m.db.LoadPAT(ownerID); err == nil {
		return pat, nil
	}
	// // state をランダムに生成する
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	state := base64.URLEncoding.EncodeToString(b)

	if err := m.db.SaveOAuthState(state, ownerID); err != nil {
		return nil, err
	}

	return nil, &ProtectionAPIError{
		Code:        ProtectionAPICodeUnAuthorized,
		Description: m.conf.AuthCodeURL(state),
	}
}

// callback は PAT を取得するフローの一部で、Owner が PAT の発行を許可したときに
// 認可サーバからリダイレクトバックされる先
func (m *patManager) callback(ownerID SubAtResSrv, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}

	// state チェック
	state := r.Form.Get("state")
	if id, err := m.db.LoadAndDeleteOAuthState(state); err != nil {
		return err
	} else if id != ownerID {
		return fmt.Errorf("invalid state (%s) for owner (%s), this state is for the other (%s)", state, ownerID, id)
	}

	// アクセストークンを取得する
	accessToken, err := m.conf.Exchange(context.Background(), r.Form.Get("code"))
	if err != nil {
		return err
	}

	// PAT を保存する
	return m.db.SavePAT(ownerID, &PAT{*accessToken})
}

func (m *patManager) client(pat *PAT) *http.Client {
	return m.conf.Client(context.Background(), &pat.Token)
}

// ResSrv の実装
type ressrv struct {
	// host はこのリソースサーバ のURL
	host  string
	authZ *AuthZSrv
	pat   *patManager
}

func (u *ressrv) CallbackForPAT(ownerID SubAtResSrv, r *http.Request) error {
	return u.pat.callback(ownerID, r)
}

func (u *ressrv) PermissionTicket(reses []ResReqForPT) (*PermissionTicket, error) {
	// Permission Ticket 発行要求を UMA に対応させる
	body, err := json.Marshal(reses)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", u.authZ.PermissionURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	// Petmission Ticket を発行するための PAT はこのリソースサーバ に対して発行されたものを使う
	// これを発行する際に、リソースサーバ はユーザを識別できないため
	pat, err := u.pat.patForResSrv()
	if err != nil {
		return nil, err
	}
	fmt.Printf("PAT for the service account is %#v\n", pat)

	// PAT をつけて permission ticket 要求を行う
	cli := u.pat.client(pat)
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusBadRequest {
		ee := new(ProtectionAPIError)
		if err := json.NewDecoder(resp.Body).Decode(ee); err != nil {
			return nil, err
		}
		return nil, ee
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected status code %s", resp.Status)
	}
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	if contentType != "application/json" {
		return nil, fmt.Errorf("content-type unmatched, expected: application/json but %s", contentType)
	}
	type t struct {
		Ticket string `json:"ticket"`
	}
	tt := new(t)
	if err := json.NewDecoder(resp.Body).Decode(tt); err != nil {
		return nil, err
	}
	return NewPermissionTicket(tt.Ticket, u.authZ.Issuer, u.host), nil
}

func (u *ressrv) List(ownerID SubAtResSrv) (resIDList []string, err error) {
	pat, err := u.pat.pat(ownerID)
	if err != nil {
		return nil, err
	}
	fmt.Printf("PAT for user(%s) is %#v\n", ownerID, pat)

	url, err := url.Parse(u.authZ.RRegURL)
	if err != nil {
		return nil, err
	}
	// このオーナに関する登録済みリソースが欲しいので Query を追記
	// Keycloak の独自設定
	q := url.Query()
	q.Add("owner", string(pat.Subject()))
	url.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, err
	}
	cli := u.pat.client(pat)
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	if contentType != "application/json" {
		return nil, fmt.Errorf("content-type unmatched, expected: application/json but %s", contentType)
	}
	ret := []string{}
	if err := json.NewDecoder(resp.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
}

func (u *ressrv) CRUD(ownerID SubAtResSrv, method string, res *Res) (*Res, error) {
	pat, err := u.pat.pat(ownerID)
	if err != nil {
		return nil, err
	}
	fmt.Printf("PAT for user(%s) is %#v\n", ownerID, pat)

	// HTTP Request の作成
	url, err := url.Parse(u.authZ.RRegURL)
	if err != nil {
		return nil, err
	}
	var req *http.Request
	// method によって要求する内容が異なる
	if method == http.MethodPost || method == http.MethodPut {
		res.OwnerManagedAccess = true
		body, err := json.Marshal(res)
		if err != nil {
			return nil, err
		}
		req, err = http.NewRequest(method, url.String(), bytes.NewBuffer(body))
		if err != nil {
			return nil, err
		}
		req.Header.Add("Content-Type", "application/json")
	} else if method == http.MethodGet || method == http.MethodDelete {
		url.Path = path.Join(url.Path, string(res.ID))
		req, err = http.NewRequest(method, url.String(), nil)
		if err != nil {
			return nil, err
		}
	}

	// HTTP Request を送信する
	b, _ := httputil.DumpRequest(req, true)
	fmt.Printf("Protection API for Resource Registration Request is\n%s\n", string(b))
	cli := u.pat.client(pat)
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err = httputil.DumpResponse(resp, true)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Protection API for Resource Registration Response is\n%s\n", string(b))

	// UMA のエラーレスポンスかチェック
	if resp.StatusCode == http.StatusNotFound ||
		resp.StatusCode == http.StatusMethodNotAllowed ||
		resp.StatusCode == http.StatusBadRequest {
		ee := new(ProtectionAPIError)
		if err := json.NewDecoder(resp.Body).Decode(ee); err != nil {
			return nil, err
		}
		return nil, ee
	}
	// UMA エラーレスポンスではないが、成功レスポンスコードでない
	isFailed := false
	switch method {
	case http.MethodDelete:
		isFailed = resp.StatusCode != http.StatusNoContent
	case http.MethodPost:
		isFailed = resp.StatusCode != http.StatusCreated
	default:
		isFailed = resp.StatusCode != http.StatusOK
	}
	if isFailed {
		return nil, fmt.Errorf("%s: %s", method, resp.Status)
	}
	// UMA 成功レスポンスなのでパースしてみる
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	if contentType != "application/json" {
		return nil, fmt.Errorf("content-type unmatched, expected: application/json but %s", contentType)
	}
	type id struct {
		ID    string `json:"_id"`
		Name  string `json:"name,omitempty"`
		Owner struct {
			ID string `json:"id"`
		} `json:"owner,omitempty"`
		OwnerManagedAccess bool `json:"ownerManagedAccess,omitempty"`
		Scopes             []struct {
			Name string `json:"name"`
		} `json:"resource_scopes,omitempty"`
	}
	i := new(id)
	if err := json.NewDecoder(resp.Body).Decode(i); err != nil {
		return nil, err
	}
	res.ID = ResID(i.ID)
	res.Name = i.Name
	res.Owner = SubAtAuthZ(i.Owner.ID)
	res.OwnerManagedAccess = i.OwnerManagedAccess
	for _, n := range i.Scopes {
		isContained := false
		for _, e := range res.Scopes {
			if e == n.Name {
				isContained = true
				break
			}
		}
		if !isContained {
			res.Scopes = append(res.Scopes, n.Name)
		}
	}
	return res, nil
}

// ProtectionAPIError は ProtectionAPI で error response のメッセージを表す
type ProtectionAPIError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	ErrorURI    string `json:"error_uri,omitempty"`
}

func (e *ProtectionAPIError) Error() string {
	return e.Code + ":" + e.Description
}

const (
	// ProtectionAPICodeNotFound は参照されたリソースが存在していないことを表す
	ProtectionAPICodeNotFound = "not_found"
	// ProtectionAPICodeMethodNotAllowed はサポートしていなHTTPメソッドの要求がきたことを表す
	ProtectionAPICodeMethodNotAllowed = "unsupported_method_type"
	// ProtectionAPICodeBadRequest はリクストに必須パラメータがないことを表す
	ProtectionAPICodeBadRequest = "invalid_request"
	// ProtectionAPICodeInvalidResID は与えられた少なくとも一つのリソース識別子が見つからないことを表す
	ProtectionAPICodeInvalidResID = "invalid_scope"
	// ProtectionAPICodeInvalidScope は要求のスコープが対象リソースに事前に登録されていないことを表す
	ProtectionAPICodeInvalidScope = "invalid_scope"
	// ProtectionAPICodeRedirection は PAT を付与されていないまたは有効でないため Protection API にアクセスできないことを表す
	// Description に認可サーバへの Redirect URL を付与することにする
	// 僕の独自設定
	ProtectionAPICodeUnAuthorized = "unauthorized"
)
