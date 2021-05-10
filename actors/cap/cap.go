package cap

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
	cdb := &cdb{
		ctxBase, sync.RWMutex{}, make(map[string]map[string]*c), make(map[string]*s),
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

	tx := conf.Tx.New(d, d, d, store)
	d.transmit = tx.Transmit

	cap := &cap{
		store: store,
		rp:    conf.CAP.Openid.New(),
	}

	r := mux.NewRouter()
	r.HandleFunc(tx.WellKnown())
	statefulPaths := tx.Router(r)
	for _, p := range statefulPaths {
		cap.statefulPaths = append(cap.statefulPaths, p)
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

func (s *sessionStoreForCAP) IdentifySubject(r *http.Request) (ctx.Sub, error) {
	session, err := s.store.Get(r, "CAP_AUTHN")
	if err != nil {
		return nil, err
	}
	sub, ok := session.Values["subject"].(string)
	if !ok {
		return nil, fmt.Errorf("ユーザを識別できない")
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
