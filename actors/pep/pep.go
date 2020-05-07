package pep

import (
	"fmt"
	"net/http"
	"soturon/actors/cap"
	"soturon/client"
	"soturon/ctxval"
	"soturon/session"
	"soturon/util"
	"strings"
)

type Conf struct {
	Addr string
}

func (c *Conf) CallbackEndponit() string {
	return "http://" + c.Addr + "/callback"
}
func (c *Conf) SubscribeEndponit() string {
	return "http://" + c.Addr + "/subscribe"
}
func (c *Conf) Endponit() string {
	return "http://" + c.Addr + "/"
}

type PEP interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
	RegisterSubsc(w http.ResponseWriter, r *http.Request)
	Callback(w http.ResponseWriter, r *http.Request)
	Subscribe(w http.ResponseWriter, r *http.Request)
	UpdateCtxForm(w http.ResponseWriter, r *http.Request)
	Approve(w http.ResponseWriter, r *http.Request)
}

func New(conf client.Config, ocredirectBackURL, registerSubURL, subscriptionEndpoint, publishIssuer, publishEndpoint string) PEP {
	return &pep{
		sm: &sessionManager{
			Manager:    session.NewManager(),
			cookieName: "policy-enforcement-point-session-id",
		},
		OC:            newOC(conf, ocredirectBackURL, registerSubURL, subscriptionEndpoint),
		CAEPRP:        newCAEPRP(publishIssuer, publishEndpoint),
		conf:          &conf,
		publishIssuer: publishIssuer,
	}
}

type pep struct {
	// sessinManager
	sm *sessionManager
	// OAuth2.0 Client in PEP for fetching token
	OC
	CAEPRP
	conf          *client.Config
	publishIssuer string
}

func (p *pep) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `
	<html>
		<head></head>
		<body>
			アクセスにはZTFでコンテキストを共有することについて同意してください。<br>
			<a href="/register">CAPへサブスク登録</a>
		</body?
	</html>	
	`)
}

func (p *pep) RegisterSubsc(w http.ResponseWriter, r *http.Request) {
	if ok := p.hasToken(r); !ok {
		// トークンを持っていなければ、トークン取得フローを始める
		p.newSession(w, r)
		return
	}
	// token があればコンテキストを取得しに行く
	ok := p.registerSubscription(r)
	if !ok {
		p.newSession(w, r)
		return
	}
	p.Consent(w)
}

func (p *pep) Consent(w http.ResponseWriter) {
	var publishScope []string
	for _, s := range p.conf.Scopes {
		if strings.HasSuffix(s, ":raw") {
			publishScope = append(publishScope, s)
		}
	}
	reqScope := "<ul>"
	for _, s := range publishScope {
		reqScope += fmt.Sprintf(`<li>
		<input type="checkbox" name="scope_%v" checked="checked">
		%v</li>
		`, s, strings.TrimSuffix(s, ":raw"))
	}
	reqScope += "</ul>"
	fmt.Fprintf(w, `
	<html><head/><body>
	CAP(%v) に以下のコンテキストを提供することに同意しますか？
	<form  action="/approve" method="POST">
		%s
		<input type="submit" name="approve" value="Approve">
		<input type="submit" name="deny" value="Deny">
	</form></body></html>`, p.publishIssuer, reqScope)
	return
}

func (p *pep) Approve(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("approve") != "Approve" {
		fmt.Fprintf(w, "CAPへコンテキストを提供することはありません")
		return
	}
	var apperovedScopes []string
	for _, s := range p.conf.Scopes {
		if sc := r.FormValue("scope_" + s); sc == "on" {
			apperovedScopes = append(apperovedScopes, s)
		}
	}

	apprprovedScopesView := "<ul>"
	for _, s := range apperovedScopes {
		apprprovedScopesView += fmt.Sprintf("<li>%v</li>", s)
	}
	apprprovedScopesView += "</ul>"

	updatedContextForm := ""
	for _, s := range apperovedScopes {
		updatedContextForm += fmt.Sprintf(`<p>%v:<input type="text" name="%v">`,
			strings.TrimSuffix(s, ":raw"), s)
	}
	fmt.Fprintf(w, `
	<html>
		<head></head>
		</body>
			<h1>同意内容</h1>
			CAPへ次のコンテキストを提供することに同意しました。
				%v
			<h1>コンテキストの変更</h1>
			自身のコンテキストを変更できます（demo用）
			<form action="/updatectx" method="POST">
			%v
			<p><input type="submit" value="submit">
			</form>
		</body>
	</html>		
	`, apprprovedScopesView, updatedContextForm)
}

func (p *pep) UpdateCtxForm(w http.ResponseWriter, r *http.Request) {
	updatectx := &cap.Context{
		UserAgent:    r.FormValue("device:useragent:raw"),
		UserLocation: r.FormValue("user:location:raw"),
	}
	p.CollextCtx("alice", updatectx)
}

// リクエストのクッキーを確認し、セッションが確立しているか、
// またそのセッションでトークンを取得しているかをチェックする
func (p *pep) hasToken(r *http.Request) bool {
	k, ok := p.sm.FindClientKeyFromCokkie(r)
	if !ok {
		// セッション未確立
		return false
	}
	if !p.HasToken(k) {
		// セッションと紐づいたトークンを持っていない
		return false
	}
	return true
}

func (p *pep) registerSubscription(r *http.Request) bool {
	// このセッションに対応したクライアントキーを取得
	k, ok := p.sm.FindClientKeyFromCokkie(r)
	if !ok {
		return false
	}
	return p.RegisterSubscription(k)
}

// セッションを新しく作り、そこでトークン取得用クライアントを作成する
func (p *pep) newSession(w http.ResponseWriter, r *http.Request) {
	// ここで作成するセッションキーはOAuth2.0 Client 識別きーも兼ねる
	k := util.RandString(30)
	http.SetCookie(w, p.sm.setClientKeyAndNewCookie(k))
	// リクエストのコンテキストに作成したClient 識別キーを追加する
	// p.Authorize はコンテキストから clientKey を取得しそれとクライアントを紐づける
	ctx := ctxval.WithClientKey(r.Context(), k)
	// トークン取得後に同じリクエストを処理できるようにする
	// リクエストパラメータはURLにのみ現れると仮定
	ctx = ctxval.WithRedirect(ctx, r.URL.String())
	p.Authorize(w, r.WithContext(ctx))
}

func (p *pep) requestPolicyDecision(actx *cap.Context) bool {
	return true
}

type sessionManager struct {
	session.Manager
	cookieName string
}

func (m *sessionManager) setClientKeyAndNewCookie(clientKey string) *http.Cookie {
	sID := m.UniqueID()
	m.Set(sID, "client_key", clientKey)
	return &http.Cookie{Name: m.cookieName, Value: sID}
}

func (m *sessionManager) FindClientKeyFromCokkie(r *http.Request) (k string, ok bool) {
	cookie, err := r.Cookie(m.cookieName)
	if err != nil {
		return "", false
	}
	return m.FindClientKey(cookie.Value)
}

func (m *sessionManager) FindClientKey(sID string) (k string, ok bool) {
	i, ok := m.FindValue(sID, "client_key")
	if !ok {
		return "", false
	}
	k, ok = i.(string)
	return
}

// func contextInfoPage(actx *cap.Context) string {
// 	ipaddrList := "<li> IPAddr"
// 	if actx.IPAddr != "" {
// 		ipaddrList += ("<ul>" + "<li>" + actx.IPAddr + "</li><li> ２回目？: " + strconv.FormatBool(actx.HaveBeenUsedThisIPAddr) + "</li></ul>")
// 	} else {
// 		ipaddrList += "IPAddr を見る権限がありません"
// 	}
// 	ipaddrList += "</li>"
// 	uaList := "<li> UserAgent"
// 	if actx.UserAgent != "" {
// 		uaList += ("<ul>" + "<li> " + actx.UserAgent + "</li><li> ２回目?: " + strconv.FormatBool(actx.HaveBeenUsedThisUA) + "</li></ul>")
// 	} else {
// 		uaList += "UserAgent を見る権限がありません"
// 	}
// 	uaList += "</li>"
// 	return fmt.Sprintf(`<html><head/><body>
// 	<ul>%v%v</ul>
// 	</body></html>`, ipaddrList, uaList)

// }
