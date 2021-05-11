package cap2

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/ctx"
	"github.com/hatake5051/ztf-prototype/ctx/tx"
	"github.com/hatake5051/ztf-prototype/openid"
)

// New は CAP のサーバを構築する
func (conf *Conf) New() *mux.Router {
	// CAP でのコンテキストデータベースを構築
	ctxBase := make(map[string]c)
	for ct, css := range conf.Tx.Contexts {
		scopeValue := make(map[string]string)
		for _, cs := range css {
			scopeValue[cs] = fmt.Sprintf("%s:init", cs)
		}
		ctxBase[ct] = c{
			typ:    ct,
			scopes: css,
			values: scopeValue,
		}
	}
	rpBase := make(map[string][]string)
	for rp, rxconf := range conf.Rx {
		var tmp []string
		for ct, css := range rxconf.Contexts {
			tmp = append(tmp, ct)

			scopeValue := make(map[string]string)
			for _, cs := range css {
				scopeValue[cs] = fmt.Sprintf("%s:init", cs)
			}
			ctxBase[ct] = c{
				typ:    ct,
				scopes: css,
				values: scopeValue,
			}
		}
		rpBase[rp] = tmp
	}
	cdb := &cdb{
		rpBase, ctxBase, sync.RWMutex{}, make(map[string]map[string]*c), make(map[string]*s),
	}

	// CAP でのセッションを管理する store を構築
	store := &sessionStoreForCAP{
		sessions.NewCookieStore([]byte("super-secret-key")),
		cdb,
	}

	d := &distributer{
		cdb:  cdb,
		rxdb: &rxdb{},
	}

	// Rx 機能を作る
	rxc := recvConf(conf.Rx)
	rx := rxc.new(d)

	cap := &cap{
		store: store,
		rp:    conf.CAP.Openid.New(),
		rx:    rx,
	}

	tx := conf.Tx.New(rx, d, cdb, store)
	d.transmit = tx.Transmit

	r := mux.NewRouter()
	r.HandleFunc(tx.WellKnown())
	statefulPaths := tx.Router(r)
	for _, p := range statefulPaths {
		cap.statefulPaths = append(cap.statefulPaths, p)
	}
	for rp, rconf := range conf.Rx {
		r.HandleFunc(fmt.Sprintf("/rx/%s/recv", rconf.Realm), cap.recvCtx(rp))
		r.HandleFunc(fmt.Sprintf("/rx/%s/rctx", rconf.Realm), cap.setCtxID(rp))
	}
	r.HandleFunc("/oidc/callback", cap.OIDCCallback)
	r.Use(cap.OIDCMW)

	return r
}

// SessionStore は CAP のセッションを管理する
type SessionStore interface {
	tx.SessionStore
	SetIdentity(r *http.Request, w http.ResponseWriter, sub ctx.Sub) error
}
type cap struct {
	rp            openid.RP
	store         SessionStore
	statefulPaths []string
	rx            *recv
}

func (c *cap) OIDCMW(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !contains(c.statefulPaths, r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if _, err := c.store.IdentifySubject(r); err != nil {
			c.store.SetRedirectBack(r, w, r.URL.String())
			c.rp.Redirect(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func contains(src []string, target string) bool {
	for _, s := range src {
		if s == target {
			return true
		}
	}
	return false
}

func (c *cap) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	idToken, err := c.rp.CallbackAndExchange(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = c.store.SetIdentity(r, w, NewCtxSub(idToken.PreferredUsername()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, c.store.LoadRedirectBack(r), http.StatusFound)
}

func (c *cap) setCtxID(rp string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sub, err := c.store.IdentifySubject(r)
		if err != nil {
			http.Error(w, "setCtxID() で、サブジェクト識別に失敗"+err.Error(), http.StatusInternalServerError)
			return
		}

		if r.Method == http.MethodGet {
			s := "<html><head/><body><h1>コンテキストのIDを設定してください</h1>"
			s += fmt.Sprintf(`<h1>CAP(%s) のコンテキスト</h1>`, rp)
			s += `<form action="" method="POST">`
			s += "<li>"
			for _, c := range c.rx.MnagedCtxList(rp, sub) {
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
				if v[0] == "" {
					continue
				}
				if err := c.rx.SetCtxID(rp, sub, k, v[0]); err != nil {
					http.Error(w, fmt.Sprintf("setctxid に失敗 %v", err), http.StatusInternalServerError)
					return
				}
			}
			return
		}
	}
}

// recvCtx は CAP からコンテキストを受け取るエンドポイント用のハンドラーを返す
// transmitter で提供先の CAP を指定する
func (c *cap) recvCtx(transmitter string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := c.rx.RecvCtx(transmitter, r); err != nil {
			fmt.Printf("cap.Recv(%s) でエラー %v\n", transmitter, err)
		}
		return
	}
}

// SessionStore の実装
type sessionStoreForCAP struct {
	store sessions.Store
	inner *cdb
}

var _ SessionStore = &sessionStoreForCAP{}

func (sm *sessionStoreForCAP) SetIdentity(r *http.Request, w http.ResponseWriter, sub ctx.Sub) error {
	session, err := sm.store.Get(r, "CAP_AUTHN")
	if err != nil {
		return err
	}
	session.Values["subject"] = sub.String()
	sm.inner.m.Lock()
	defer sm.inner.m.Unlock()
	sm.inner.subs[sub.String()] = &s{sub.String(), make(map[caep.RxID]caep.EventSubject)}
	if err := session.Save(r, w); err != nil {
		return err
	}
	return nil
}

func (sm *sessionStoreForCAP) IdentifySubject(r *http.Request) (ctx.Sub, error) {
	session, err := sm.store.Get(r, "CAP_AUTHN")
	if err != nil {
		return nil, err
	}
	sub, ok := session.Values["subject"].(string)
	if !ok {
		return nil, fmt.Errorf("ユーザを識別できない")
	}
	sm.inner.m.Lock()
	defer sm.inner.m.Unlock()
	if _, ok := sm.inner.subs[sub]; !ok {
		sm.inner.subs[sub] = &s{sub, make(map[caep.RxID]caep.EventSubject)}
	}
	return NewCtxSub(sub), nil
}

func (s *sessionStoreForCAP) LoadRedirectBack(r *http.Request) (redirectURL string) {
	session, err := s.store.Get(r, "CAP_AUTHN")
	if err != nil {
		return ""
	}
	fmt.Printf("Load Session %#v\n", session.Values)
	red, ok := session.Values["return-address"].(string)
	if !ok {
		return ""
	}
	return red
}

func (s *sessionStoreForCAP) SetRedirectBack(r *http.Request, w http.ResponseWriter, redirectURL string) error {
	session, err := s.store.Get(r, "CAP_AUTHN")
	if err != nil {
		return err
	}
	session.Values["return-address"] = redirectURL
	fmt.Printf("Set Session %#v\n", session.Values)
	if err := session.Save(r, w); err != nil {
		return err
	}
	return nil
}
