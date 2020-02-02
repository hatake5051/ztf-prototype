package cap

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"mime"
	"net/http"
	"soturon/authorizer"
	"soturon/client"
	"soturon/ctxval"
	"soturon/session"
	"sync"
)

type CAPRP interface {
	// IdP の認証同意ページへユーザをリダイレクト
	Authenticate(w http.ResponseWriter, r *http.Request)
	// IdP から認可コードを受け取り、IDトークンと交換する
	Callback(w http.ResponseWriter, r *http.Request)
	// IdP から取得したIDトークンがあるか、また有効であるか検証する
	HasIDToken(rpkey string) bool
	// IdP userInfo endpoint からユーザ情報を取得する
	FetchUserInfo(rpkey string) (*authorizer.User, bool)
}

func newCAPRP(conf *client.Config, redirectBacks map[string]string, userInfoURL string) CAPRP {
	return &caprp{
		sm: &rpSessionManager{
			Manager:    session.NewManager(),
			cookieName: "context-attribute-oidc-relyingparty-session-id",
		},
		rm: &rpManager{
			conf: conf,
			db:   make(map[string]client.RP),
		},
		redirectBackURLs: redirectBacks,
		userInfoURL:      userInfoURL,
	}
}

type caprp struct {
	sm               *rpSessionManager
	rm               *rpManager
	redirectBackURLs map[string]string
	userInfoURL      string
}

func (c *caprp) Authenticate(w http.ResponseWriter, r *http.Request) {
	// リクエストコンテキストの中にRPキーは含まれている
	k, _ := ctxval.RPKey(r.Context())
	// clientID, _ := ctxval.ClientID(r.Context())
	// log.Printf("caprp clientid: %v", clientID)

	rp := c.rm.create(r.Context(), k)
	http.SetCookie(w, c.sm.setRPKeyAndNewCookie(k))
	rp.RedirectToAuthenticator(w, r)
}

func (c *caprp) Callback(w http.ResponseWriter, r *http.Request) {
	// セッションと紐づいたRPを取得
	cookie, err := r.Cookie(c.sm.cookieName)
	if err != nil {
		return
	}
	k, ok := c.sm.getRPKey(cookie.Value)
	if !ok {
		return
	}
	rp, ok := c.rm.find(k)
	if !ok {
		return
	}
	// リクエストに含まれる認可コードを元にトークンを取得
	// 取得するとIDトークンはRPに蓄積される
	if err := rp.ExchangeCodeForIDToken(r); err != nil {
		return
	}
	// IDトークンを取得したので、コンテキスト取得のためのトークン取得フローに戻す
	// それは記憶しておいた /authorize に 戻してあげれば良い
	redirect, ok := ctxval.Redirect(rp.Context())
	// log.Printf("carp callback r: %#v", redirect)
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (c *caprp) HasIDToken(rpKey string) bool {
	// rpKey t紐づいたRPを取り出す
	rp, ok := c.rm.find(rpKey)
	if !ok {
		return false
	}
	// そのRPがIDトークンを持っているか確認する
	return rp.HasIDToken()
}

func (c *caprp) FetchUserInfo(rpKey string) (*authorizer.User, bool) {
	rp, ok := c.rm.find(rpKey)
	if !ok {
		return nil, false
	}
	// UserInfo Endpoint にGetリクエスト
	req, err := http.NewRequest("GET", c.userInfoURL, nil)
	if err != nil {
		return nil, false
	}
	// Token をリクエストに付与
	rp.SetIDTokenToHeader(&req.Header)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, false
	}
	if status := resp.StatusCode; status < 200 || status >= 300 {
		return nil, false
	}
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, false
	}
	if contentType != "application/json" {
		return nil, false
	}
	user := &authorizer.User{}
	if err := json.Unmarshal(body, user); err != nil {
		return nil, false
	}
	// UserInfo レスポンスをデシリアライズして返す
	return user, true

}

type rpSessionManager struct {
	session.Manager
	cookieName string
}

func (sm *rpSessionManager) setRPKeyAndNewCookie(rpKey string) *http.Cookie {
	sID := sm.UniqueID()
	sm.Set(sID, "rpKey", rpKey)
	return &http.Cookie{Name: sm.cookieName, Value: sID}

}

func (sm *rpSessionManager) getRPKey(sID string) (rpKey string, ok bool) {
	i, ok := sm.FindValue(sID, "rpKey")
	if !ok {
		return "", false
	}
	if rpKey, ok = i.(string); !ok {
		return "", false
	}
	return
}

type rpManager struct {
	conf *client.Config
	db   map[string]client.RP
	sync.RWMutex
}

func (rm *rpManager) create(ctx context.Context, k string) client.RP {
	rm.Lock()
	defer rm.Unlock()
	r := rm.conf.RP(ctx)
	rm.db[k] = r
	return r
}

func (rm *rpManager) find(k string) (r client.RP, ok bool) {
	rm.RLock()
	defer rm.RUnlock()
	r, ok = rm.db[k]
	return
}
