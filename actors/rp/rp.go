package rp

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/hatake5051/ztf-prototype/ac"
)

// New は CAP とコンテキストを連携してアクセス制御を行うサービスを展開する RP を生成する
func New(idp string, ctrl ac.Controller) *mux.Router {
	rp := &rp{
		store: sessions.NewCookieStore([]byte("super-secret-key")),
		idp:   idp,
		ctrl:  ctrl,
	}
	r := mux.NewRouter()
	r.Use(rp.PEPMW)
	r.HandleFunc("/", rp.ServeHTTP)
	s := r.PathPrefix("/auth").Subrouter()
	sSubPIP := s.PathPrefix("/pip/sub").Subrouter()
	sSubPIP.HandleFunc("/0/callback", rp.OIDCCallback(""))
	sCtxPIP := s.PathPrefix("/pip/ctx").Subrouter()
	// TODO loop
	sCtxPIP.HandleFunc("/0/callback", rp.OIDCCallback("http://localhost:9090"))
	sCtxPIP.HandleFunc("/0/recv", rp.RecvCtx("http://localhost:9090"))
	return r
}

type rp struct {
	store *sessions.CookieStore
	idp   string
	ctrl  ac.Controller
}

func (rp *rp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "ようこそ！")
	return
}
func (rp *rp) parseAccessRequest(r *http.Request) (ac.Resource, ac.Action, error) {
	aa := r.URL.Query().Get("a")
	if aa == "" {
		aa = "dummy-action"
	}
	a := &action{aa}
	rr := r.URL.Query().Get("r")
	if rr == "" {
		rr = "dummy-res"
	}
	res := &resource{rr}
	return res, a, nil
	// return nil, nil, fmt.Errorf("no matched to the request %v", r)
}

type action struct {
	id string
}

func (a *action) ID() string {
	return a.id
}

type resource struct {
	id string
}

func (res *resource) ID() string {
	return res.id
}

func (rp *rp) PEPMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/auth") {
			next.ServeHTTP(w, r)
			return
		}
		session, err := rp.store.Get(r, "cookie-pep")
		if err != nil {
			http.Error(w, "session: cookie-pep is not exist in store :"+err.Error(), http.StatusInternalServerError)
			return
		}
		res, a, err := rp.parseAccessRequest(r)
		if err != nil {
			http.Error(w, "parseAccessRequest failed: :"+err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Printf("session.ID: %s Name: %s\n", session.ID, session.Name())
		if err := rp.ctrl.AskForAuthorization(session.Name(), res, a); err != nil {
			if err, ok := err.(ac.Error); ok {
				switch err.ID() {
				case ac.RequestDenied:
					http.Error(w, fmt.Sprintf("the action(%s) on the resource(%s) is not permitted", a.ID(), res.ID()), http.StatusForbidden)
					return
				case ac.SubjectForCtxUnAuthorizedButReqSubmitted:
					http.Error(w, fmt.Sprintf("コンテキスト所有者に確認をとりに行っています"), http.StatusAccepted)
					return
				case ac.SubjectNotAuthenticated:
					rp.OIDCRedirect(err.Option(), w, r)
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

func (rp *rp) RecvCtx(key string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := rp.ctrl.CtxAgent(key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := a.RecvCtx(r); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		return
	}
}

func (rp *rp) OIDCRedirect(key string, w http.ResponseWriter, r *http.Request) {
	name := "cookie-redirect-"
	if key != "" {
		if strings.Contains(key, "9090") {
			name += "cap1"
		} else {
			tmp := strings.Split(key, "/")
			name += tmp[len(tmp)-1]
		}
	} else {
		name = name + "idp"
	}
	session, err := rp.store.Get(r, name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.AddFlash(r.URL.String())
	if err := session.Save(r, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var a ac.AuthNAgent
	var e error
	if key == "" {
		a, e = rp.ctrl.SubAgent(rp.idp)
	} else {
		a, e = rp.ctrl.CtxAgent(key)
	}
	if e != nil {
		http.Error(w, e.Error(), http.StatusInternalServerError)
		return
	}
	a.Redirect(w, r)
	return

}

func (rp *rp) OIDCCallback(key string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := "cookie-redirect-"
		if key != "" {
			if strings.Contains(key, "9090") {
				name += "cap1"
			} else {
				tmp := strings.Split(key, "/")
				name += tmp[len(tmp)-1]
			}
		} else {
			name = name + "idp"
		}
		session, err := rp.store.Get(r, name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var flashes []interface{}
		if flashes = session.Flashes(); len(flashes) == 0 {
			http.Error(w, "無効なリクエスト: session がない", http.StatusInternalServerError)
			return
		}
		redirecturl := flashes[0].(string)

		session2, err := rp.store.Get(r, "cookie-pep")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var a ac.AuthNAgent
		var e error
		if key == "" {
			a, e = rp.ctrl.SubAgent(rp.idp)
		} else {
			a, e = rp.ctrl.CtxAgent(key)
		}
		if e != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := a.Callback(session2.Name(), r); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := sessions.Save(r, w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, redirecturl, http.StatusFound)
	}
}
