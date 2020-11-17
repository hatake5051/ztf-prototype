package cap

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/uma"
)

type Conf struct {
	Issuer       string
	OIDCRPID     string
	OIDCRPSecret string
	Host         string
}

func (c *Conf) New() *mux.Router {
	umaConf := &uma.ResSrvConf{
		AuthZSrv: c.Issuer,
		ClientCred: struct {
			ID     string
			Secret string
		}{c.OIDCRPID, c.OIDCRPSecret},
	}
	u := umaConf.New()
	cap := &cap{
		host:  c.Host,
		store: sessions.NewCookieStore([]byte("super-secret-key")),
		rp:    NewOIDCRP(c.Issuer, c.OIDCRPID, c.OIDCRPSecret, c.Host+"/oidc/callback"),
		uma:   u,
	}
	tr := (&caep.Conf{Host: c.Host}).New(u)
	r := mux.NewRouter()
	r.HandleFunc("/", cap.ServeHTTP)
	r.HandleFunc("/.well-known/sse-configuration/", tr.WellKnown)
	sCAEP := r.PathPrefix("/set").Subrouter()
	sCAEP.PathPrefix("/stream").Methods("GET").HandlerFunc(tr.GetCtxStreamConfig)
	sCAEP.PathPrefix("/status/{spagID}").Methods("GET").HandlerFunc(tr.GetStreamStatus)
	sCAEP.PathPrefix("/subject:add").Methods("POST").HandlerFunc(tr.AddSub)
	s := r.PathPrefix("/auth").Subrouter()
	r.PathPrefix("/oidc").Subrouter().HandleFunc("/callback", cap.OIDCCallback)
	s.Use(cap.OIDCMW)
	s.HandleFunc("/list", cap.CtxList)
	s.HandleFunc("/reg", cap.CtxReg)

	return r
}

type cap struct {
	host  string
	store *sessions.CookieStore
	rp    OIDCRP
	uma   uma.ResSrv
}

type subjectKey string

func (c *cap) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sub, ok := r.Context().Value(subjectKey("sub")).(string)
	if !ok {
		http.Error(w, "認証MWを潜り抜けている！！", http.StatusForbidden)
		return
	}
	fmt.Fprintf(w, "%#v", sub)
}

func (c *cap) CtxList(w http.ResponseWriter, r *http.Request) {
	sub, ok := r.Context().Value(subjectKey("sub")).(string)
	if !ok {
		http.Error(w, "認証MWを潜り抜けている！！", http.StatusForbidden)
		return
	}
	res, err := c.uma.List(sub)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s := "<html><head/><body><h1>コンテキスト一覧</h1>"
	s += "<ul>"
	for _, rr := range res {
		s += "<li>" + rr + "</li>"
	}
	s += "</ul></body></html>"
	// んー、<> をエスケープしない
	w.Write([]byte(s))
}

func (c *cap) CtxReg(w http.ResponseWriter, r *http.Request) {
	sub, ok := r.Context().Value(subjectKey("sub")).(string)
	if !ok {
		http.Error(w, "認証MWを潜り抜けている！！", http.StatusForbidden)
		return
	}
	q := r.URL.Query().Get("id")
	var res *uma.Res
	if q == "1" {
		res = &uma.Res{
			Name:   "ctx1",
			Owner:  sub,
			Scopes: []string{"scope1", "scope2"},
		}
	} else if q == "2" {
		res = &uma.Res{
			Name:   "ctx2",
			Owner:  sub,
			Scopes: []string{"scope111", "scope2"},
		}
	} else {
		http.Error(w, "クエリが正しくないよ", http.StatusBadRequest)
		return
	}
	res, err := c.uma.CRUD("POST", res)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s := "<html><head/><body><h1>コンテキスト一覧</h1>"
	s += "<ul>"
	s += "<li>ID: " + res.ID + "</li>"
	s += "<li>Name: " + res.Name + "</li>"
	s += "<li>Owner: " + res.Owner + "</li>"
	s += fmt.Sprintf("<li>%s: %t</li>", "OwnerManagedAccess", res.OwnerManagedAccess)
	s += fmt.Sprintf("<li>%s: %s</li>", "Scopes", strings.Join(res.Scopes, " "))
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
		sub, ok := session.Values["subject"].(string)
		if !ok {
			session.Values["return-address"] = r.URL.String()
			session.Save(r, w)
			c.rp.Redirect(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), subjectKey("sub"), sub)))
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
	session.Values["subject"] = idToken.Subject
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
