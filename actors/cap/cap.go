package cap

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/hatake5051/ztf-prototype/ctx"
	"github.com/hatake5051/ztf-prototype/ctx/tx"
	"github.com/hatake5051/ztf-prototype/openid"
)

// New は CAP のサーバを構築する
func (conf *Conf) New() *mux.Router {
	// CAP でのセッションを管理する store を構築
	store := &sessionStoreForCAP{
		sessions.NewCookieStore([]byte("super-secret-key")),
	}

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

	d := &distributer{
		cdb: &cdb{
			cBase: ctxBase,
		},
		rxdb: &rxdb{},
	}

	tx := conf.Tx.New(d, d, d, store)
	d.transmit = tx.Transmit

	cap := &cap{
		store: store,
		rp:    conf.CAP.Openid.to().New(),
		all:   d.All,
	}

	r := mux.NewRouter()
	r.HandleFunc(tx.WellKnown())
	tx.Router(r)

	r.Handle("/", cap)
	// r.HandleFunc("/ctx/recv", cap.Recv)
	r.HandleFunc("/oidc/callback", cap.OIDCCallback)
	r.Use(cap.OIDCMW)

	return r
}

// SessionStore は CAP のセッションを管理する
type SessionStore interface {
	tx.SessionStore
	PreferredName(r *http.Request) (string, error)
	SetIdentity(r *http.Request, w http.ResponseWriter, sub ctx.Sub, preferredName string) error
}

type cap struct {
	rp    openid.RP
	store SessionStore
	all   func() []ctx.Type
}

func (c *cap) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, err := c.store.PreferredName(r)
	if err != nil {
		http.Error(w, "ユーザを識別できません", http.StatusUnauthorized)
		return
	}
	s := fmt.Sprintf("<html><head/><body><h1>%sさん、こんにちは</h1>", name)
	s += `<a href="/list">コンテキストを管理する</a><br/>`
	s += `<a href="/uma/list>認可サーバへ登録済みコンテキスト一覧</a>`
	s += "</body></html>"
	w.Write([]byte(s))

}

func (c *cap) OIDCMW(next http.Handler) http.Handler {
	protectedPathList := []string{
		"/", "/list", "/uma/list", "/uma/ctx",
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !contains(protectedPathList, r.URL.Path) {
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
	err = c.store.SetIdentity(r, w, NewCtxSub(idToken.Subject()), idToken.PreferredUsername())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, c.store.LoadRedirectBack(r), http.StatusFound)
}

// func (c *cap) Recv(w http.ResponseWriter, r *http.Request) {
// 	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	if contentType != "application/secevent+jwt" {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	tok, err := jwt.Parse(r.Body, jwt.WithVerify(jwa.HS256, []byte("for-agent-sending")))
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	v, ok := tok.Get("events")
// 	if !ok {
// 		http.Error(w, "送られてきたSETに events property がない", http.StatusInternalServerError)
// 		return
// 	}
// 	e, ok := caep.NewSETEventsClaimFromJson(v)
// 	if !ok {
// 		http.Error(w, "送られてきたSET events property のパースに失敗", http.StatusInternalServerError)
// 		return
// 	}
// 	c.distr.RecvAndDistribute(e)
// }

func (c *cap) CtxList(w http.ResponseWriter, r *http.Request) {
	name, err := c.store.PreferredName(r)
	if err != nil {
		http.Error(w, "ユーザを識別できない", http.StatusInternalServerError)
		return
	}

	s := fmt.Sprintf("<html><head/><body><h1>%sさん、こんにちは</h1>", name)
	s += "<h1>コンテキスト一覧</h1>"
	s += "<ul>"
	for _, ctxType := range c.all() {
		s += fmt.Sprintf("<li>ctx(%s)は認可サーバで保護", ctxType)

		s += `されていません。=> <form action="/uma/ctx" method="POST">`
		s += fmt.Sprintf(`<input type="hidden" name="t" value="%s"> `, ctxType)
		s += `<button type="submit">保護する</button></form>`

		s += "</li>"
	}
	s += "</ul></body></html>"
	// んー、<> をエスケープしない
	w.Write([]byte(s))
}

// SessionStore の実装
type sessionStoreForCAP struct {
	store sessions.Store
}

var _ SessionStore = &sessionStoreForCAP{}

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

func (s *sessionStoreForCAP) PreferredName(r *http.Request) (string, error) {
	session, err := s.store.Get(r, "CAP_AUTHN")
	if err != nil {
		return "", err
	}

	name, ok := session.Values["preferredName"].(string)
	if !ok {
		return "", fmt.Errorf("ユーザを識別できない")
	}
	return name, nil
}
func (s *sessionStoreForCAP) SetIdentity(r *http.Request, w http.ResponseWriter, sub ctx.Sub, preferredName string) error {
	session, err := s.store.Get(r, "CAP_AUTHN")
	if err != nil {
		return err
	}
	session.Values["preferredName"] = preferredName
	session.Values["subject"] = sub.String()
	if err := session.Save(r, w); err != nil {

		return err
	}
	return nil
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
