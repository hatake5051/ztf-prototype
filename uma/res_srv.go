package uma

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"

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

// ResSrv は UMA-enabled なリソースサーバを表す
type ResSrv interface {
	// CRUD は method に基づいて res を Restful に操作する
	CRUD(method string, res *Res) (*Res, error)
	// List は owner が UMA AuthZSrv に登録したコンテキストを一覧する
	List(owner string) (resIDList []string, err error)
	// PermissionTicket は reses にアクセスを求めている情報をまとめて Permission Ticket に変換する
	PermissionTicket(reses []ResReqForPT) (*PermissionTicket, error)
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
		authZ: authZSrv,
		conf:  clientcredConf}
}

type ressrv struct {
	host  string
	authZ *AuthZSrv
	conf  *clientcredentials.Config
}

func (u *ressrv) PermissionTicket(reses []ResReqForPT) (*PermissionTicket, error) {
	client := u.conf.Client(context.Background())
	body, err := json.Marshal(reses)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", u.authZ.PermissionURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("permission から %s", resp.Status)
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
	return &PermissionTicket{
		Ticket: tt.Ticket,
		InitialOption: &struct {
			AuthZSrv string
			ResSrv   string
		}{u.authZ.Issuer, u.host},
	}, nil

}

func (u *ressrv) List(owner string) (resIDList []string, err error) {
	client := u.conf.Client(context.Background())
	resp, err := client.Get(u.authZ.RRegURL + "?owner=" + owner)
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
	client := u.conf.Client(context.Background())

	if method == "POST" {
		res.OwnerManagedAccess = true
	}
	body, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}
	url := u.authZ.RRegURL
	if method != "POST" {
		url += "/" + res.ID
	}
	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if method == "DELETE" {
		if resp.StatusCode != http.StatusNoContent {
			return nil, fmt.Errorf("%s: %s", method, resp.Status)
		}
		return nil, nil
	}

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}
	if method == "POST" && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("%s: %s", method, resp.Status)
	} else if method != "POST" && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", method, resp.Status)
	}
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	if contentType != "application/json" {
		return nil, fmt.Errorf("content-type unmatched, expected: application/json but %s", contentType)
	}
	type id struct {
		ID string `json:"_id"`
	}
	i := new(id)
	if err := json.Unmarshal(body, i); err != nil {
		return nil, err
	}
	res.ID = i.ID
	return res, nil

}
