package pep

import (
	"fmt"
	"net/http"
	"soturon/actors/cap"
	"soturon/client"
	"soturon/ctxval"
	"soturon/session"
	"soturon/util"
	"strconv"
)

type PEP interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
	Callback(w http.ResponseWriter, r *http.Request)
}

func New(conf client.Config, ocredirectBackURL, contextEndpoint string) PEP {
	return &pep{
		sm: &sessionManager{
			Manager:    session.NewManager(),
			cookieName: "policy-enforcement-point-session-id",
		},
		OC: newOC(conf, ocredirectBackURL, contextEndpoint),
	}
}

type pep struct {
	// sessinManager
	sm *sessionManager
	// OAuth2.0 Client in PEP for fetching token
	OC
}

// PEP のエントリポイント。現状は、SPへアクセスする際に必ず通るハンドラ。
func (p *pep) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if ok := p.front(r); !ok {
		// トークンを持っていなければ、トークン取得フローを始める
		p.newSession(w, r)
		return
	}
	// token があればコンテキストを取得しに行く
	actx, ok := p.fetchContext(r)
	if !ok {
		p.newSession(w, r)
		return
	}
	// PE に ctx に基づいた Policy Decision を尋ねる
	if ok := p.requestPolicyDecision(actx); !ok {
		fmt.Fprint(w, "access denied")
		return
	}
	fmt.Fprintf(w, contextInfoPage(actx))
}

// リクエストのクッキーを確認し、セッションが確立しているか、
// またそのセッションでトークンを取得しているかをチェックする
func (p *pep) front(r *http.Request) bool {
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

func (p *pep) fetchContext(r *http.Request) (*cap.Context, bool) {
	// このセッションに対応したクライアントキーを取得
	k, ok := p.sm.FindClientKeyFromCokkie(r)
	if !ok {
		return nil, false
	}
	return p.FetchContext(k)
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

func contextInfoPage(actx *cap.Context) string {
	ipaddrList := "<li> IPAddr"
	if actx.IPAddr != "" {
		ipaddrList += ("<ul>" + "<li>" + actx.IPAddr + "</li><li> ２回目？: " + strconv.FormatBool(actx.HaveBeenUsedThisIPAddr) + "</li></ul>")
	} else {
		ipaddrList += "IPAddr を見る権限がありません"
	}
	ipaddrList += "</li>"
	uaList := "<li> UserAgent"
	if actx.UserAgent != "" {
		uaList += ("<ul>" + "<li> " + actx.UserAgent + "</li><li> ２回目?: " + strconv.FormatBool(actx.HaveBeenUsedThisUA) + "</li></ul>")
	} else {
		uaList += "UserAgent を見る権限がありません"
	}
	uaList += "</li>"
	return fmt.Sprintf(`<html><head/><body>
	<ul>%v%v</ul>
	</body></html>`, ipaddrList, uaList)

}
