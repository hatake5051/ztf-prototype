package rp

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/hatake5051/ztf-prototype/ac"
	"github.com/hatake5051/ztf-prototype/ac/controller"
	"github.com/hatake5051/ztf-prototype/ac/pdp"
	"github.com/hatake5051/ztf-prototype/ac/pep"
	"github.com/hatake5051/ztf-prototype/actors/rp/pip"
)

type ACConf struct {
	PIPConf *pip.Conf
	PDPConf *pdp.Conf
}

func (c *ACConf) New(prefix string) AC {
	repo := pip.NewRepo()
	pip, err := c.PIPConf.New(repo)
	if err != nil {
		panic(fmt.Sprintf("PIP の構成に失敗 %v", err))
	}
	pdp, err := c.PDPConf.New()
	if err != nil {
		panic(fmt.Sprintf("PDP の構成に失敗 %v", err))
	}
	ctrl := controller.New(pip, pdp)
	idp := c.PIPConf.IssuerList[0]
	var capList []string
	for k, _ := range c.PIPConf.CAP2RP {
		capList = append(capList, k)
	}
	store := sessions.NewCookieStore([]byte("super-secret-key"))
	pep := pep.New(prefix, idp, capList, ctrl, store, &helper{})
	return pep
}

type AC interface {
	Protect(r *mux.Router)
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
