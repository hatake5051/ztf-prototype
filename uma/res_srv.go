package uma

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"

	"golang.org/x/oauth2/clientcredentials"
)

// ResSrvConf は UMA-enabled なリソースサーバの設定情報
type ResSrvConf struct {
	// AuthZSrv は UMA-enabled な認可サーバの名前
	AuthZSrv string
	// ClientCred は Protection API Token を取得するためのクライアント情報
	// 簡単のためClientCredential でPATを取得すると想定
	ClientCred struct {
		ID     string
		Secret string
	}
}

// New は設定情報から ResSrv を構成する
// UMAAuthZSrv の設定に失敗するとパニック
func (c *ResSrvConf) New() ResSrv {
	authZSrv, err := NewAuthZSrv(c.AuthZSrv)
	if err != nil {
		panic(fmt.Sprintf("ResSrv の構成に失敗(UMA認可サーバの設定を取得できなかった) err:%v", err))
	}
	clientcredConf := &clientcredentials.Config{
		ClientID:     c.ClientCred.ID,
		ClientSecret: c.ClientCred.Secret,
		TokenURL:     authZSrv.TokenURL,
	}
	return &ressrv{
		authZ:   authZSrv,
		patConf: clientcredConf}
}

// ResSrv は UMA-enabled なリソースサーバを表す
type ResSrv interface {
	// CRUD は method に基づいて res を Restful に操作する
	CRUD(method string, res *Res) (*Res, error)
	// List は owner が UMA AuthZSrv に登録したコンテキストを一覧する
	List(owner string) (resIDList []string, err error)
	// PermissionTicket は reses にアクセスを求めている情報をまとめて Permission Ticket に変換する
	PermissionTicket(reses []ResReqForPT) (*PermissionTicket, error)
}

// ProtectionAPIError は ProtectionAPI で error response のメッセージを表す
type ProtectionAPIError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	ErrorURI    string `json:"error_uri,omitempty"`
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
)

func (e *ProtectionAPIError) Error() string {
	return e.Code + ":" + e.Description
}

// ResSrv の実装
type ressrv struct {
	host    string
	authZ   *AuthZSrv
	patConf *clientcredentials.Config
}

func (u *ressrv) PermissionTicket(reses []ResReqForPT) (*PermissionTicket, error) {
	body, err := json.Marshal(reses)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", u.authZ.PermissionURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	client := u.patConf.Client(context.Background())
	resp, err := client.Do(req)
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

func (u *ressrv) List(owner string) (resIDList []string, err error) {
	url, err := url.Parse(u.authZ.RRegURL)
	if err != nil {
		return nil, err
	}
	url.Query().Add("owner", owner)
	client := u.patConf.Client(context.Background())
	resp, err := client.Get(url.String())
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

func (u *ressrv) CRUD(method string, res *Res) (*Res, error) {
	// HTTP Request の作成
	if method == http.MethodPost {
		res.OwnerManagedAccess = true
	}
	body, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}
	url, err := url.Parse(u.authZ.RRegURL)
	if err != nil {
		return nil, err
	}
	if method != http.MethodPost {
		url.Path = path.Join(url.Path, res.ID)
	}
	req, err := http.NewRequest(method, url.String(), bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	// HTTP Request を送信する
	client := u.patConf.Client(context.Background())
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	dump, _ := httputil.DumpResponse(resp, true)
	fmt.Printf("uma crud resp %s\n", dump)
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
		ID                  string `json:"_id"`
		UserAccessPolicyURI string `json:"user_access_policy_uri,omitempty"`
	}
	i := new(id)
	if err := json.NewDecoder(resp.Body).Decode(i); err != nil {
		return nil, err
	}
	res.ID = i.ID
	res.UserAccessPolicyURI = i.UserAccessPolicyURI
	return res, nil

}
