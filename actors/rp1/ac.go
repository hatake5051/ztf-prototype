package rp1

import (
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/hatake5051/ztf-prototype/ac"
	"github.com/hatake5051/ztf-prototype/ac/controller"
	"github.com/hatake5051/ztf-prototype/ac/pep"
	"github.com/hatake5051/ztf-prototype/uma"
)

func (conf *Conf) New(prefix string) pep.PEP {
	store := sessions.NewCookieStore([]byte("super-secret-key"))
	// PIP の構成
	sstore := &iSessionStoreForSPIP{r: make(map[string]*s)}
	cstore := &iSessionStoreForCPIP{
		r:               make(map[string]map[string]*cs),
		spipSM:          sstore,
		store:           store,
		sessionNme:      "AC_PEP_SESSION",
		sessionValueKey: "PEP_SESSION_ID"}
	db := &iCtxDB{
		ctxs:    make(map[string]map[string]*c),
		capBase: make(map[string]map[string][]string),
		ctxBase: make(map[string][]string),
	}
	for cap, cconf := range conf.PIP.Ctx {
		db.Init(cap, cconf.Rx.Contexts)
		if cconf.Tx.Contexts != nil {
			db.Init(cap, cconf.Tx.Contexts)
		}
	}
	udb := &iUMADB{
		pts:  make(map[string]*uma.PermissionTicket),
		rpts: make(map[string]*uma.RPT),
	}

	pip := conf.PIP.New(sstore, cstore, db, udb, db, &rxdb{}, &iTranslaterForTx{db})
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
