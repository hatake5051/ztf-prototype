package rp

import (
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/hatake5051/ztf-prototype/ac"
	"github.com/hatake5051/ztf-prototype/ac/controller"
	"github.com/hatake5051/ztf-prototype/ac/pep"
)

func (conf *Conf) New(prefix string) pep.PEP {
	repo := NewRepo()
	// PIP の構成
	sstore := &iSessionStoreForSPIP{repo, "subpip-sm"}
	cstore := &iSessionStoreForCPIP{repo, "ctxpip-sm"}
	db := &iCtxDB{r: repo, keyModifier: "ctxpip-db"}
	for cap, cconf := range conf.PIP.Ctx {
		db.Init(cap, cconf.Rx.Contexts)
	}
	udb := &iUMADB{repo, "ctxpip-umadb"}
	pip := conf.PIP.New(sstore, cstore, db, udb, db)
	// PDP の構成
	pdp, err := conf.PDP.New()
	if err != nil {
		panic(fmt.Sprintf("PDP の構成に失敗 %v", err))
	}
	// controller の構成
	ctrl := controller.New(pip, pdp)

	// PEP の構成
	var idpList []string
	for idp, _ := range conf.PIP.Sub {
		idpList = append(idpList, idp)
	}
	var capList []string
	for cap, _ := range conf.PIP.Ctx {
		capList = append(capList, cap)
	}
	store := sessions.NewCookieStore([]byte("super-secret-key"))
	pep := pep.New(prefix, idpList, capList, ctrl, store, &helper{})
	return pep
}

type helper struct{}

func (h *helper) ParseAccessRequest(r *http.Request) (ac.Resource, ac.Action, error) {
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

type s struct {
	Raw string
}

var _ ac.Subject = &s{}

func (s *s) ID() string {
	return s.Raw
}
