package rp2

import (
	"fmt"

	"github.com/hatake5051/ztf-prototype/ac"
	"github.com/hatake5051/ztf-prototype/ac/pdp"
	"github.com/hatake5051/ztf-prototype/ctx"
)

// 実験用の pdp を実装する
type mypdp struct{}

var _ pdp.PDP = &mypdp{}

func (pdp *mypdp) NotifiedOfRequest(s ac.Subject, r ac.Resource, a ac.Action) (reqctxs []ac.ReqContext, deny bool) {
	fmt.Println("pdp.NotifiedRequest start...")
	fmt.Printf("sub(%s) wants to do action(%s) on res(%s) without context\n", s.ID(), a.ID(), r.ID())
	req1 := &reqctx{"http://cap1.ztf-proto.k3.ipv6.mobi/ctxtype/device-location", []string{"used:ip"}}
	return []ac.ReqContext{req1.toACReq()}, false
}

func (pdp *mypdp) Decision(s ac.Subject, r ac.Resource, a ac.Action, clist []ctx.Ctx) error {
	fmt.Println("pdp.Decision start...")
	fmt.Printf("sub(%s) wants to do action(%s) on res(%s) with context\n", s.ID(), a.ID(), r.ID())
	for _, c := range clist {
		fmt.Printf("  ctx(%s)\n", c.Type())
		for _, s := range c.Scopes() {
			fmt.Printf("    scope(%s): %s\n", s.String(), c.Value(s))
		}
	}
	return nil
}

type reqctx struct {
	Type   string
	Scopes []string
}

func (c *reqctx) toACReq() ac.ReqContext {
	return &wrap{c}
}

type wrap struct {
	c *reqctx
}

func (c *wrap) Type() ctx.Type {
	return ctx.NewCtxType(c.c.Type)
}
func (c *wrap) Scopes() []ctx.Scope {
	var ret []ctx.Scope
	for _, s := range c.c.Scopes {
		ret = append(ret, ctx.NewCtxScope(s))
	}
	return ret
}
