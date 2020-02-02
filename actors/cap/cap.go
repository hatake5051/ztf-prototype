package cap

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"mime"
	"net/http"
	"net/url"
	"soturon/authorizer"
	"soturon/client"
	"soturon/ctxval"
	"soturon/session"
	"soturon/util"
	"strings"
)

type CAP interface {
	// トークンを持った要求に対し、コンテキストを返す
	ServeHTTP(w http.ResponseWriter, r *http.Request)
	// Context 取得トークンのための認可コードをユーザの同意を元に発行する
	Authorize(w http.ResponseWriter, r *http.Request)
	// ユーザの同意を確認し、認可コードを発行する
	Approve(w http.ResponseWriter, r *http.Request)
	Token(w http.ResponseWriter, r *http.Request)
	IntroSpect(w http.ResponseWriter, r *http.Request)
	// Callback はIdPが発行する認可コードの受け取り先
	Callback(w http.ResponseWriter, r *http.Request)
	RegisterSubsc(w http.ResponseWriter, r *http.Request)
	CollectCtx(w http.ResponseWriter, r *http.Request)
}

func New(registration map[string]*client.Config, conf *client.Config, rpRedirectURLs map[string]string, userInfoURL string, issueURL string) CAP {
	ctxs := NewCtxStore()
	cap := &cap{
		a: authorizer.New(registration),
		sm: &sessionManager{
			Manager:    session.NewManager(),
			cookieName: "context-attribute-provider-session-id",
		},
		CAPRP:   newCAPRP(conf, rpRedirectURLs, userInfoURL),
		caepsvc: newCAEPSVC(issueURL, ctxs),
		ctxs:    ctxs,
	}
	return cap
}

type cap struct {
	a  authorizer.Authorizer
	sm *sessionManager
	CAPRP
	caepsvc CAEPSVC
	ctxs    ContextStore
}

func (c *cap) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "index page")
}

func (c *cap) RegisterSubsc(w http.ResponseWriter, r *http.Request) {
	introToken, ok := c.tokenIntrospect(r)
	if !ok {
		http.Error(w, fmt.Sprintf("cannot introspect token %#v", r.Header.Get("Authorization")), http.StatusBadRequest)
		return
	}
	registeringSubscriptionEndpoint := r.FormValue("url")
	c.caepsvc.RegisterSubscription(registeringSubscriptionEndpoint, introToken.Scope)
	userctx, _ := c.ctxs.Load(introToken.UserName)
	c.caepsvc.InitPublish(registeringSubscriptionEndpoint, introToken, userctx)
	w.WriteHeader(http.StatusCreated)
}

func (c *cap) tokenIntrospect(r *http.Request) (*authorizer.IntroToken, bool) {
	// トークンを取り出す
	bearerPlusToken := strings.Split(r.Header.Get("Authorization"), " ")
	t := bearerPlusToken[1]
	// トークンが正しいかIntroSpect endpoint に尋ねる
	req, err := http.NewRequest("POST", "http://localhost:9001/introspect", strings.NewReader(url.Values{"token": {t}}.Encode()))
	if err != nil {
		return nil, false
	}
	// 尋ね方はフォーム形式のPOSTメソッド
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	// Response を検証
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
	// Response をデシリアライズ
	introToken := new(authorizer.IntroToken)
	if err := json.Unmarshal(body, introToken); err != nil {
		return nil, false
	}
	log.Printf("cap.tokenIntroSpect token: %#v", introToken)
	return introToken, true
}

func (c *cap) Authorize(w http.ResponseWriter, r *http.Request) {
	// 認可コードリクエストに対応する認証情報があるか確認
	rpKey, ok := c.sm.findRPKeyFromCokkie(r)
	if !ok {
		// 認証情報がなければ、認証取得 OIDC flow を始める
		c.newSession(w, r)
		return
	}
	// 認証識別子のIDトークンがあるか確認
	if !c.HasIDToken(rpKey) {
		// なければ、IDトークン取得フローを新しく始める
		c.newSession(w, r)
		return
	}
	// IDトークンがあれば、IdP にユーザ情報を問うためのトークンを持っている
	// そのトークンを使って詳細なユーザ情報を取得しにいく
	user, ok := c.FetchUserInfo(rpKey)
	if !ok {
		// ダメになることはないだろう...
		return
	}
	// トークン発行を承認するかユーザに尋ねるための情報をリクエストから取得
	req, err := c.a.Authorize(user, w, r)
	if err != nil {
		return
	}
	// ユーザに同意を促すページをレスポンス
	fmt.Fprint(w, consentPage(req, user))
}

func (c *cap) CollectCtx(w http.ResponseWriter, r *http.Request) {
	c.caepsvc.CollectCtx(w, r)
}

func (c *cap) newSession(w http.ResponseWriter, r *http.Request) {
	// セッションIDをクリエイト
	k := util.RandString(30)
	http.SetCookie(w, c.sm.setRPKeyAndNewCookie(k))
	// リクエストコンテキストにRPキーとクライアントIDを付与
	// RP キーはリクエストごとに認証フローを始めるRPを識別するため
	ctx := ctxval.WithRPKey(r.Context(), k)
	// client-id はIDトークン取得後にどの PEPOC にリダイレクトすれば良いか記憶するため
	ctx = ctxval.WithRedirect(ctx, r.URL.String())
	// OIDC 認証フローを開始
	c.Authenticate(w, r.WithContext(ctx))
}

func (c *cap) Approve(w http.ResponseWriter, r *http.Request) {
	c.a.Approve(w, r)
}

func (c *cap) Token(w http.ResponseWriter, r *http.Request) {
	c.a.IssueToken(w, r)
}

func (c *cap) IntroSpect(w http.ResponseWriter, r *http.Request) {
	c.a.IntroSpect(w, r)
}

type sessionManager struct {
	session.Manager
	cookieName string
}

func (m *sessionManager) setRPKeyAndNewCookie(rpKey string) *http.Cookie {
	sID := m.UniqueID()
	m.Set(sID, "rp_key", rpKey)
	return &http.Cookie{Name: m.cookieName, Value: sID}
}

func (m *sessionManager) findRPKeyFromCokkie(r *http.Request) (k string, ok bool) {
	cookie, err := r.Cookie(m.cookieName)
	if err != nil {
		return "", false
	}
	i, ok := m.FindValue(cookie.Value, "rp_key")
	if !ok {
		return "", false
	}
	k, ok = i.(string)
	return
}

func consentPage(c *client.Config, user *authorizer.User) string {
	hello := fmt.Sprintf("%v さんこんにちは。<Br>", user.Name)

	reqScope := "<ul>"
	for _, s := range c.Scopes {
		reqScope += fmt.Sprintf(`<li>
		<input type="checkbox" name="scope_%v" checked="checked">
		%v</li>
		`, s, s)
	}
	reqScope += "</ul>"
	return fmt.Sprintf(`
	<html><head/><body>
	%v<br>
	%v が以下の権限を要求しています
	<form  action="/approve" method="POST">
		%s
		<input type="submit" name="approve" value="Approve">
		<input type="submit" name="deny" value="Deny">
	</form></body></html>`, hello, c.ClientID, reqScope)
}
