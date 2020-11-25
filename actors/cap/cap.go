package cap

import (
	"fmt"
	"mime"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/openid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

// New は CAP のサーバを構築する
func (c *Conf) New() *mux.Router {
	store := sessions.NewCookieStore([]byte("super-secret-key"))
	u := c.UMA.to().New()
	us, db := newUMASrv(u, c.CAP.Contexts, store)
	jwtURL := "http://idp.ztf-proto.k3.ipv6.mobi/auth/realms/context-share/protocol/openid-connect/certs"
	v := &addsubverifier{
		verifier{jwtURL},
		u,
		db,
	}
	recvRepo := &trStreamDB{db: make(map[string]caep.Receiver)}
	var eventsupported []string
	for ctxID := range c.CAP.Contexts {
		eventsupported = append(eventsupported, ctxID)
	}
	for recvID, v := range c.CAEP.Receivers {
		recvRepo.Save(&caep.Receiver{
			ID:   recvID,
			Host: v.Host,
			StreamConf: &caep.StreamConfig{
				Iss:             c.CAEP.Metadata.Issuer,
				Aud:             []string{v.Host},
				EventsSupported: eventsupported,
			},
		})
	}
	recvs := &recvs{
		inner: recvRepo,
		db:    make(map[string][]string),
	}
	statusRepo := &trStatusDB{db: make(map[string]map[string]caep.StreamStatus)}
	d := &distributer{
		inner: statusRepo,
		ctxs:  c.CAP.Contexts,
		recvs: recvs,
	}
	tr := c.CAEP.to().New(recvs, d, v)
	d.tr = tr
	cap := &cap{
		ctxs:     c.CAP.Contexts,
		store:    store,
		rp:       c.CAP.Openid.to().New(),
		rpForUMA: c.CAEP.Openid.to().New(),
		db:       db,
		distr:    d,
	}
	r := mux.NewRouter()
	tr.Router(r)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/hello/", http.StatusFound) })
	s1 := r.PathPrefix("/hello").Subrouter()
	r.PathPrefix("/oidc").Subrouter().HandleFunc("/callback", cap.OIDCCallback)
	s1.Use(cap.OIDCMW)
	s1.HandleFunc("/", cap.ServeHTTP)
	s := r.PathPrefix("/auth").Subrouter()
	r.HandleFunc("/uma/oidc/callback", cap.OIDCCallbackForUMAProtectionAPI)
	s.Use(cap.OIDCMWForUMAProtectionAPI)
	s.HandleFunc("/list", cap.CtxList)
	s.HandleFunc("/ctx", us.CRUD)
	r.HandleFunc("/ctx/recv", cap.Recv)
	return r
}

type cap struct {
	ctxs     map[string][]string
	store    sessions.Store
	rp       openid.RP
	rpForUMA openid.RP
	db       resDB
	distr    *distributer
}

func (c *cap) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session, err := c.store.Get(r, "CAP_AUTHN")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name, ok := session.Values["name"].(string)
	if !ok {
		http.Error(w, "認証MWを潜り抜けている！！", http.StatusForbidden)
		return
	}
	s := fmt.Sprintf("<html><head/><body><h1>%sさん、こんにちは</h1>", name)
	s += `<a href="/auth/list">コンテキストを管理する</a>`
	s += "</body></html>"
	w.Write([]byte(s))

}

func (c *cap) OIDCMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/callback" {
			next.ServeHTTP(w, r)
			return
		}
		session, err := c.store.Get(r, "CAP_AUTHN")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, ok := session.Values["name"].(string)
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
	session, err := c.store.Get(r, "CAP_AUTHN")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.Values["name"] = idToken.PreferredUsername()
	if err := session.Save(r, w); err != nil {
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

func (c *cap) Recv(w http.ResponseWriter, r *http.Request) {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if contentType != "application/secevent+jwt" {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tok, err := jwt.Parse(r.Body, jwt.WithVerify(jwa.HS256, []byte("for-agent-sending")))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	v, ok := tok.Get("events")
	if !ok {
		http.Error(w, "送られてきたSETに events property がない", http.StatusInternalServerError)
		return
	}
	e, ok := caep.NewSETEventsClaimFromJson(v)
	if !ok {
		http.Error(w, "送られてきたSET events property のパースに失敗", http.StatusInternalServerError)
		return
	}
	c.distr.RecvAndDistribute(e)
}

func (c *cap) CtxList(w http.ResponseWriter, r *http.Request) {
	session, err := c.store.Get(r, "UMA_PROTECTION_API_AUTHN")
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

func (c *cap) OIDCMWForUMAProtectionAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "uma/oidc/callback" {
			next.ServeHTTP(w, r)
			return
		}
		session, err := c.store.Get(r, "UMA_PROTECTION_API_AUTHN")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, ok := session.Values["subject"].(string)
		if !ok {
			session.Values["return-address"] = r.URL.String()
			session.Save(r, w)
			c.rpForUMA.Redirect(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (c *cap) OIDCCallbackForUMAProtectionAPI(w http.ResponseWriter, r *http.Request) {
	idToken, err := c.rpForUMA.CallbackAndExchange(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session, err := c.store.Get(r, "UMA_PROTECTION_API_AUTHN")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.Values["subject"] = idToken.Subject()
	session.Values["name"] = idToken.PreferredUsername()
	if err := session.Save(r, w); err != nil {
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
