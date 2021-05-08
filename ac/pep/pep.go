package pep

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/hatake5051/ztf-prototype/ac"
	"github.com/hatake5051/ztf-prototype/ac/controller"
	"github.com/hatake5051/ztf-prototype/ac/pip"
)

// PEP は Policy Enforcement Point を表すのに加えて、 PIP で必要なエンドポイントを設定する
type PEP interface {
	// Protect は r を保護する
	// r に MW で保護し、r に RecvCtx と Callback のエンドポイントを設定する
	Protect(r *mux.Router)
}

// New は PEP を構築する。
// idpList は PDP がユーザ識別のために使う IdP を URL のリストで指定する。
// capList は PDP が認可判断のために使う CAP を列挙する。
// ctxList は PIP が認可判断のために収集するコンテキストのリストを CAP をキーにしてもつ
func New(prefix string,
	idpList []string,
	capList []string,
	ctrl controller.Controller,
	store sessions.Store,
	helper Helper,
) PEP {
	return &pep{
		prefix:  prefix,
		capList: capList,
		idpList: idpList,
		ctrl:    ctrl,
		store:   store,
		helper:  helper,
	}
}

// Helper は http.Request をアクセス制御部で使う構造体に変換する
// HTTP要求をどのリソースへどういったアクションを試みているかにパースする。
type Helper interface {
	ParseAccessRequest(r *http.Request) (ac.Resource, ac.Action, error)
}

// pep は PEP の実装
type pep struct {
	// prefix は RP の base URL のうち、 アクセス制御部のために用意された URL の prefix path を表す
	prefix string
	// idpList はこのアクセス制御部で利用可能な IdP のリストを表す
	idpList []string
	// capList はこのアクセス制御部で利用可能な CAP のリストを表す
	capList           []string
	ctrl              controller.Controller
	store             sessions.Store
	helper            Helper
	protectedPathList []string
	collectors        []func(r *http.Request)
}

func (p *pep) Protect(r *mux.Router) {
	ssub := r.PathPrefix(path.Join("/", p.prefix, "pip/sub")).Subrouter()
	for i, idp := range p.idpList {
		ssub.PathPrefix(fmt.Sprintf("/%d/login", i)).HandlerFunc(p.redirect(idp))
		ssub.PathPrefix(fmt.Sprintf("/%d/callback", i)).HandlerFunc(p.callback(idp))
	}

	sctx := r.PathPrefix(path.Join("/", p.prefix, "pip/ctx")).Subrouter()

	for i, cap := range p.capList {
		sctx.PathPrefix(fmt.Sprintf("/%d/recv", i)).HandlerFunc(p.recvCtx(cap))
		sctx.PathPrefix(fmt.Sprintf("/%d/rctx", i)).HandlerFunc(p.setCtxID(cap))
		a, err := p.ctrl.CtxAgent(cap)
		if err != nil {
			panic("ありえん気がするわ " + err.Error())
		}
		agent, ok := a.(pip.TxRxCtxAgent)
		if ok {
			pa, h := agent.WellKnown()
			r.Handle(path.Join("/.well-known", pa), h)
			plist := agent.Router(sctx.PathPrefix(fmt.Sprintf("/%d/tx", i)).Subrouter())
			p.protectedPathList = append(p.protectedPathList, plist...)
			p.collectors = append(p.collectors, agent.Collect)
		}
	}
	r.Use(p.mw)
}

const (
	snPEP      = "AC_PEP_SESSION"
	sidPEP     = "PEP_SESSION_ID"
	snRedirect = "AC_PEP_REDIRECT"
)

// getSessionID は session IDをなければ発行する。
func (p *pep) getSessionID(r *http.Request, w http.ResponseWriter) (string, error) {
	session, err := p.store.Get(r, snPEP)
	if err != nil {
		return "", nil
	}
	// セッションに PEP が用いるセッションIDがあればそれを返す
	if v, ok := session.Values[sidPEP]; ok {
		return v.(string), nil
	}
	// なければ、 PEP 用のセッションIDを新しく作成する
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	sessionID := base64.StdEncoding.EncodeToString(b)
	session.Values[sidPEP] = sessionID
	if err := session.Save(r, w); err != nil {
		return "", err
	}
	return sessionID, nil
}

// mw は保護するミドルウェア
// このミドルウェアを通過するとは、PDPが承認したということである。
// 内部で Redirect を利用する。
func (p *pep) mw(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("request comming with %s\n", r.URL.String())

		// RP が地震で回収できるコンテキストを集める
		for _, collector := range p.collectors {
			collector(r)
		}

		// prefix から始まる URL path は mw 自身が使用している URL なので保護しない
		if strings.HasPrefix(r.URL.Path, path.Join("/", p.prefix)) {
			if contains(r.URL.Path, p.protectedPathList) {
				// protectedPathList に含まれるところは認証情報が欲しいところ
				if _, err := p.getSessionID(r, w); err != nil {
					http.Error(w, "session: cookie-pep is not exist in store :"+err.Error(), http.StatusInternalServerError)
					return
				}
			}
			next.ServeHTTP(w, r)
			return
		}

		sessionID, err := p.getSessionID(r, w)
		if err != nil {
			http.Error(w, "session: cookie-pep is not exist in store :"+err.Error(), http.StatusInternalServerError)
			return
		}

		// RP に対してユーザがどんなアクセス要求をしているのかを判定する
		res, a, err := p.helper.ParseAccessRequest(r)
		if err != nil {
			http.Error(w, "parseAccessRequest failed: :"+err.Error(), http.StatusForbidden)
			return
		}

		if err := sessions.Save(r, w); err != nil {
			http.Error(w, fmt.Sprintf("セッションの保存に失敗 %v", err), http.StatusInternalServerError)
			return
		}

		// アクセス判断を担う Controller に認可結果を尋ねる
		if err := p.ctrl.AskForAuthorization(sessionID, res, a); err != nil {
			if err, ok := err.(ac.Error); ok {
				switch err.ID() {
				case ac.RequestDenied:
					http.Error(w, fmt.Sprintf("the action(%s) on the resource(%s) is not permitted", a.ID(), res.ID()), http.StatusForbidden)
					return
				case ac.SubjectForCtxUnAuthorizedButReqSubmitted:
					http.Error(w, fmt.Sprintf("コンテキスト所有者に確認をとりに行っています"), http.StatusAccepted)
					return
				case ac.CtxIDNotRegistered:
					var index int
					for i, cap := range p.capList {
						if cap == err.Option() {
							index = i
							break
						}
					}
					http.Redirect(w, r, fmt.Sprintf("/%s/pip/ctx/%d/rctx", p.prefix, index), http.StatusFound)
					return
				case ac.SubjectNotAuthenticated:
					p.login(w, r)
					return
				case ac.IndeterminateForCtxNotFound:
					http.Error(w, fmt.Sprintf("少し時間を置いてからアクセスしてください"), http.StatusAccepted)
				default:
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (p *pep) setCtxID(cap string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := p.ctrl.CtxAgent(cap)
		if err != nil {
			http.Error(w, "ctxagentが見つからない"+err.Error(), http.StatusInternalServerError)
			return
		}
		session, err := p.getSessionID(r, w)
		if err != nil {
			p.login(w, r)
			return
		}
		agent := a.(pip.RxCtxAgent)

		if r.Method == http.MethodGet {
			s := "<html><head/><body><h1>コンテキストのIDを設定してください</h1>"
			s += fmt.Sprintf(`<h1>CAP(%s) のコンテキスト</h1>`, cap)
			s += `<form action="" method="POST">`
			s += "<li>"
			for _, c := range agent.ManagedCtxList(session) {
				s += fmt.Sprintf(`コンテキストの種類 (%[1]s) のID <input type="text" name="%[1]s" placeholder="%[2]s"><br/>`, c.Type().String(), c.ID().String())
			}
			s += "</li>"
			s += `<input type="submit" value="設定する">`
			s += "</form></body></html>"

			w.Write([]byte(s))
			return
		}
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				http.Error(w, fmt.Sprintf("setctxid の parseform に失敗 %v", err), http.StatusInternalServerError)
				return
			}
			for k, v := range r.Form {
				if err := agent.SetCtxID(session, k, v[0]); err != nil {
					http.Error(w, fmt.Sprintf("setctxid に失敗 %v", err), http.StatusInternalServerError)
					return
				}
			}
			http.Redirect(w, r, r.URL.String(), http.StatusFound)
			return
		}
	}
}

// recvCtx は CAP からコンテキストを受け取るエンドポイント用のハンドラーを返す
// transmitter で提供先の CAP を指定する
func (p *pep) recvCtx(transmitter string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := p.ctrl.CtxAgent(transmitter)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		switch a := a.(type) {
		case pip.RxCtxAgent:
			if err := a.RecvCtx(r); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		case pip.TxRxCtxAgent:
			if err := a.RecvCtx(r); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		return
	}
}

func (p *pep) login(w http.ResponseWriter, r *http.Request) {
	session, err := p.store.Get(r, snRedirect)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// callback で戻ってきた後にどの URL に遷移すべきかを一時的に記憶する
	session.AddFlash(r.URL.String())
	if err := session.Save(r, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s := "<html><head/><body><h1>ログインする IdP を選択</h1>"
	s += "<ul>"
	for index, idp := range p.idpList {
		s += fmt.Sprintf(`<li>%s で<a href="/%s/pip/sub/%d/login">ログイン</a></li>`, idp, p.prefix, index)
	}
	s += "</ul></body></html>"
	w.Write([]byte(s))
}

// redirect は IdP にユーザをリダイレクトする
// host でリダイレクト先の IdP を指定する
func (p *pep) redirect(host string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, e := p.ctrl.AuthNAgent(host)
		if e != nil {
			http.Error(w, e.Error(), http.StatusInternalServerError)
			return
		}
		a.Redirect(w, r)
	}
}

// callback は IdP からリダイレクトバックする先のエンドポイントに対応する http.HandlerFunc を返す
func (p *pep) callback(host string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// コールバックを受けるエージェントを選別
		a, e := p.ctrl.AuthNAgent(host)
		if e != nil {
			http.Error(w, e.Error(), http.StatusInternalServerError)
			return
		}

		// sessionID と openid.IDToken を紐付ける
		sessionID, err := p.getSessionID(r, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := a.Callback(sessionID, r); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Redirect back する先があるかチェック
		session, err := p.store.Get(r, snRedirect)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// リダイレクト用のクッキーは不要に
		session.Options.MaxAge = -1

		// callback した後にどの URL に遷移すべきかをセッションから取得する
		if flashes := session.Flashes(); len(flashes) > 0 {
			redirecturl := flashes[0].(string)
			if err := sessions.Save(r, w); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, redirecturl, http.StatusFound)
			return
		}
		if err := session.Save(r, w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte("認証成功"))
	}
}
func contains(src string, target []string) bool {
	for _, s := range target {
		if s == src {
			return true
		}
	}
	return false
}
