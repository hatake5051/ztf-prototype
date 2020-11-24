package cap

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/hatake5051/ztf-prototype/openid"
)

// New は CAP のサーバを構築する
func (c *Conf) New() *mux.Router {
	store := sessions.NewCookieStore([]byte("super-secret-key"))
	u := c.UMA.to().New()
	us, db := newUMASrv(u, c.CAP.Contexts, store)
	jwtURL := "http://idp.ztf-proto.k3.ipv6.mobi/auth/realms/ztf-proto/protocol/openid-connect/certs"
	tr := newTr(c.CAP.Contexts, c.CAEP, jwtURL, u, db)
	cap := &cap{
		ctxs:  c.CAP.Contexts,
		store: store,
		rp:    c.CAEP.Openid.to().New(),
		db:    db,
	}
	r := mux.NewRouter()
	tr.Router(r)
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/auth/list", http.StatusFound) })
	r.PathPrefix("/oidc").Subrouter().HandleFunc("/callback", cap.OIDCCallback)
	s := r.PathPrefix("/auth").Subrouter()
	s.Use(cap.OIDCMW)
	s.HandleFunc("/list", cap.CtxList)
	s.HandleFunc("/ctx", us.CRUD)
	return r
}

type cap struct {
	ctxs  map[string][]string
	store sessions.Store
	rp    openid.RP
	db    resDB
}

func (c *cap) CtxList(w http.ResponseWriter, r *http.Request) {
	session, err := c.store.Get(r, "cookie-auth")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sub, ok := session.Values["subject"].(string)
	name, ok := session.Values["name"].(string)
	if !ok {
		http.Error(w, "認証MWを潜り抜けている！！", http.StatusForbidden)
		return
	}

	s := fmt.Sprintf("<html><head/><body><h1>%sさん、こんにちは</h1>", name)
	s += "<h1>コンテキスト一覧</h1>"
	s += "<ul>"
	for ctxID := range c.ctxs {
		s += fmt.Sprintf("<li>ctx(%s)は認可サーバで保護", ctxID)
		if _, err := c.db.Load(sub, ctxID); err == nil {
			s += fmt.Sprintf(`されています。 => <a href="/auth/ctx?id=%s">詳細を見る</a>`, ctxID)
		} else {
			s += `されていません。=> <form action="/auth/ctx" method="POST">`
			s += fmt.Sprintf(`<input type="hidden" name="id" value="%s"> `, ctxID)
			s += `<button type="submit">保護する</button></form>`
		}
		s += "</li>"
	}
	s += "</ul></body></html>"
	// んー、<> をエスケープしない
	w.Write([]byte(s))
}

func (c *cap) OIDCMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/callback" {
			next.ServeHTTP(w, r)
			return
		}
		session, err := c.store.Get(r, "cookie-auth")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, ok := session.Values["subject"].(string)
		if !ok {
			session.Values["return-address"] = r.URL.String()
			session.Save(r, w)
			c.rp.Redirect(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (c *cap) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	idToken, err := c.rp.CallbackAndExchange(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session, err := c.store.Get(r, "cookie-auth")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("%#v\n", idToken)
	session.Values["subject"] = idToken.Subject()
	session.Values["name"] = idToken.PreferredUsername()
	if err := session.Save(r, w); err != nil {
		log.Printf("error %#v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ret, ok := session.Values["return-address"].(string)
	if !ok {
		http.Error(w, "return-address missing", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, ret, http.StatusFound)
}
