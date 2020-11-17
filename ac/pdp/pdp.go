package pdp

import (
	"fmt"

	"github.com/hatake5051/ztf-prototype/ac"
)

type Conf struct {
}

func (c *Conf) New() (ac.PDP, error) {
	return &pdp{}, nil
}

type pdp struct{}

func (pdp *pdp) NotifiedOfRequest(s ac.Subject, r ac.Resource, a ac.Action) (reqctxs []ac.ReqContext, deny bool) {
	fmt.Println("pdp.NotifiedRequest start...")
	fmt.Printf("sub(%s) wants to do action(%s) on res(%s) without context\n", s.ID(), a.ID(), r.ID())
	req1 := &reqctx{"ctx1", []string{"scope1", "scope2"}}
	req2 := &reqctx{"ctx2", []string{"scope111", "scope2"}}
	return []ac.ReqContext{req1.toACReq(), req2.toACReq()}, false
}

func (pdp *pdp) Decision(s ac.Subject, r ac.Resource, a ac.Action, clist []ac.Context) error {
	fmt.Println("pdp.Decision start...")
	fmt.Printf("sub(%s) wants to do action(%s) on res(%s) with context\n", s.ID(), a.ID(), r.ID())
	for _, c := range clist {
		fmt.Printf("  ctx(%s)\n", c.ID())
		for id, s := range c.ScopeValues() {
			fmt.Printf("    scope(%s): %s\n", id, s)
		}
	}
	return nil
}

type reqctx struct {
	ID     string
	Scopes []string
}

func (c *reqctx) toACReq() ac.ReqContext {
	return &wrap{c}
}

type wrap struct {
	c *reqctx
}

func (c *wrap) ID() string {
	return c.c.ID
}
func (c *wrap) Scopes() []string {
	return c.c.Scopes
}
