package pep

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"soturon/client"
	"soturon/ctxval"
	"soturon/session"
	"strings"
	"sync"
)

type OC interface {
	// 認可コード取得フローを行う
	Authorize(w http.ResponseWriter, r *http.Request)
	// 認可コード取得後にトークン取得フローを始める
	Callback(w http.ResponseWriter, r *http.Request)
	// clientKey が k の OAtuth2.0 Client が有効なトークンを取得しているか
	HasToken(k string) bool
	// clientKey が k の OAtuth2.0 Client に CAEP Subsciber を登録させる
	RegisterSubscription(clientKey string) bool
}

func newOC(conf client.Config, redirectBackURL, registerSubURL, subscriptionURL string) OC {
	return &pepoc{
		sm: &ocSessionManager{
			Manager:    session.NewManager(),
			cookieName: "policy-enforcement-oauth2-client-session-id",
		},
		cm: &clientManager{
			conf: conf,
			db:   make(map[string]client.Client),
		},
		redirectBackURL: redirectBackURL,
		subscriptinoURL: subscriptionURL,
		registerSubURL:  registerSubURL,
	}
}

type pepoc struct {
	sm              *ocSessionManager
	cm              *clientManager
	redirectBackURL string
	subscriptinoURL string
	registerSubURL  string
}

func (p *pepoc) Authorize(w http.ResponseWriter, r *http.Request) {
	// Authorize は pep.newSession から呼び出される
	// 必ずコンテキストの中に clientKey が存在している
	k, _ := ctxval.ClientKey(r.Context())
	// ユーザ用のクライアントを作成する
	c := p.cm.create(r.Context(), k)
	// セッションを作成する
	sID := p.sm.UniqueID()
	// そのセッションにクライアント識別子を記憶
	p.sm.setClientKey(sID, k)
	http.SetCookie(w, &http.Cookie{Name: p.sm.cookieName, Value: sID})
	// CAP Authorizer にリダイレクト
	c.RedirectToAuthorizer(w, r)
}

func (p *pepoc) Callback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(p.sm.cookieName)
	if err != nil {
		return
	}
	k, ok := p.sm.getClientKey(cookie.Value)
	if !ok {
		return
	}
	c, ok := p.cm.find(k)
	if !ok {
		return
	}
	if err := c.ExchangeCodeForToken(r); err != nil {
		return
	}
	// トークンを取得したので、PEPのPolicyDecisionフローに戻す
	// それは記憶しておいた /entrypoint に 戻してあげれば良い
	redirect, ok := ctxval.Redirect(c.Context())
	log.Printf("pepoc callback r: %#v", redirect)
	http.Redirect(w, r, redirect, http.StatusFound)
	return
}

func (p *pepoc) HasToken(k string) bool {
	c, ok := p.cm.find(k)
	if !ok {
		return false
	}
	return c.HasToken()
}

func (p *pepoc) RegisterSubscription(clientKey string) bool {
	// 対応するクライアントを検索
	c, ok := p.cm.find(clientKey)
	if !ok {
		return false
	}
	// Context Provider のエンドポイントへのリクエストを作成
	req, err := http.NewRequest("POST", p.registerSubURL, strings.NewReader(url.Values{"url": {p.subscriptinoURL}}.Encode()))
	if err != nil {
		return false
	}
	// 尋ね方はフォーム形式のPOSTメソッド
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// もちろんトークンをリクエストに付与
	c.SetTokenToHeader(&req.Header)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	if status := resp.StatusCode; status != 201 {
		return false
	}
	return true
}

type ocSessionManager struct {
	session.Manager
	cookieName string
}

func (sm *ocSessionManager) setClientKey(sID, clientKey string) {
	sm.Set(sID, "clientKey", clientKey)
}

func (sm *ocSessionManager) getClientKey(sID string) (clientKey string, ok bool) {
	i, ok := sm.FindValue(sID, "clientKey")
	if !ok {
		return "", false
	}
	if clientKey, ok = i.(string); !ok {
		return "", false
	}
	return
}

type clientManager struct {
	conf client.Config
	db   map[string]client.Client
	sync.RWMutex
}

func (cm *clientManager) create(ctx context.Context, k string) client.Client {
	cm.Lock()
	defer cm.Unlock()
	c := cm.conf.Client(ctx)
	cm.db[k] = c
	return c
}

func (cm *clientManager) find(k string) (c client.Client, ok bool) {
	cm.RLock()
	defer cm.RUnlock()
	c, ok = cm.db[k]
	return
}
