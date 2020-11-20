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

type PEP interface {
	Protect(r *mux.Router)
	MW(next http.Handler) http.Handler
	RecvCtx(transmitter string) http.HandlerFunc
	Redirect(host string, isCAP bool) http.HandlerFunc
	Callback(host string, isCAP bool) http.HandlerFunc
}

func New(prefix string,
	idp string,
	capList []string,
	ctrl controller.Controller,
	store sessions.Store,
	helper Helper,
) PEP {
	return &pep{
		prefix:  prefix,
		capList: capList,
		idp:     idp,
		ctrl:    ctrl,
		store:   store,
		helper:  helper,
	}
}

type Helper interface {
	ParseAccessRequest(r *http.Request) (ac.Resource, ac.Action, error)
}

type pep struct {
	prefix  string
	idp     string
	capList []string
	ctrl    controller.Controller
	store   sessions.Store
	helper  Helper
}

func (p *pep) Protect(r *mux.Router) {
	r.Use(p.MW)
	r.PathPrefix(path.Join("/", p.prefix, "pip/sub/0/callback")).HandlerFunc(p.Callback(p.idp, false))
	s := r.PathPrefix(path.Join("/", p.prefix, "pip/ctx")).Subrouter()
	for i, cap := range p.capList {
		s.PathPrefix(fmt.Sprintf("/%d/callback", i)).HandlerFunc(p.Callback(cap, true))
		s.PathPrefix(fmt.Sprintf("/%d/recv", i)).HandlerFunc(p.RecvCtx(cap))
	}
}

const (
	snPEP      = "AC_PEP_SESSION"
	sidPEP     = "PEP_SESSION_ID"
	snRedirect = "AC_PEP_REDIRECT"
)

func (p *pep) getSessionID(r *http.Request) (string, error) {
	session, err := p.store.Get(r, snPEP)
	if err != nil {
		return "", nil
	}
	if v, ok := session.Values[sidPEP]; ok {
		fmt.Printf("sessionID exist %s\n", v)
		return v.(string), nil
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	sessionID := base64.StdEncoding.EncodeToString(b)
	fmt.Printf("sessionID newed %s\n", sessionID)
	session.Values[sidPEP] = sessionID
	return sessionID, nil
}

func (p *pep) MW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("request comming with %s\n", r.URL.String())
		if strings.HasPrefix(r.URL.Path, path.Join("/", p.prefix)) {
			next.ServeHTTP(w, r)
			return
		}
		sessionID, err := p.getSessionID(r)
		if err != nil {
			http.Error(w, "session: cookie-pep is not exist in store :"+err.Error(), http.StatusInternalServerError)
			return
		}
		res, a, err := p.helper.ParseAccessRequest(r)
		if err != nil {
			http.Error(w, "parseAccessRequest failed: :"+err.Error(), http.StatusForbidden)
			return
		}
		if err := sessions.Save(r, w); err != nil {
			http.Error(w, fmt.Sprintf("セッションの保存に失敗 %v", err), http.StatusInternalServerError)
			return
		}
		if err := p.ctrl.AskForAuthorization(sessionID, res, a); err != nil {
			if err, ok := err.(ac.Error); ok {
				switch err.ID() {
				case ac.RequestDenied:
					http.Error(w, fmt.Sprintf("the action(%s) on the resource(%s) is not permitted", a.ID(), res.ID()), http.StatusForbidden)
					return
				case ac.SubjectForCtxUnAuthorizedButReqSubmitted:
					http.Error(w, fmt.Sprintf("コンテキスト所有者に確認をとりに行っています"), http.StatusAccepted)
					return
				case ac.SubjectNotAuthenticated:
					if err.Option() == "" {
						p.Redirect(p.idp, false)(w, r)
					} else {
						p.Redirect(err.Option(), true)(w, r)
					}
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

func (p *pep) RecvCtx(transmitter string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := p.ctrl.CtxAgent(transmitter)
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
func (p *pep) Redirect(host string, isCAP bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := p.store.Get(r, snRedirect)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		session.AddFlash(r.URL.String())
		if err := session.Save(r, w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var a pip.AuthNAgent
		var e error
		if isCAP {
			a, e = p.ctrl.CtxAgent(host)

		} else {
			a, e = p.ctrl.SubAgent(host)
		}
		if e != nil {
			http.Error(w, e.Error(), http.StatusInternalServerError)
			return
		}
		a.Redirect(w, r)
	}
}

func (p *pep) Callback(host string, isCAP bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// コールバックを受けるエージェントを選別
		var a pip.AuthNAgent
		var e error
		if isCAP {
			a, e = p.ctrl.CtxAgent(host)

		} else {
			a, e = p.ctrl.SubAgent(host)
		}
		if e != nil {
			http.Error(w, e.Error(), http.StatusInternalServerError)
			return
		}

		// sessionID と openid.IDToken を紐付ける
		sessionID, err := p.getSessionID(r)
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
