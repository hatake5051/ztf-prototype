package pdp

import (
	"fmt"

	"github.com/hatake5051/ztf-prototype/ac"
	"github.com/hatake5051/ztf-prototype/ctx"
)

// PDP は認可判断の主体
type PDP interface {
	// NotifiedOfRequest は認可判断に必要なコンテキストはなにか PIP に伝える
	// すでに認証が終わり、どのユーザがどのリソースへ何のアクションを行いたいか理解している前提
	// この時点でアクセス拒否が明らかなら deny = true を返す
	NotifiedOfRequest(ac.Subject, ac.Resource, ac.Action) (reqctxs []ac.ReqContext, deny bool)
	// Decision は認可判断を行う
	// 認可判断の結果アクセスを許可するなら nil を返す
	Decision(ac.Subject, ac.Resource, ac.Action, []ctx.Ctx) error
}

// Conf は PDP 構築のための設定を表す
type Conf struct {
}

// New は設定情報から PDP を構築する
func (c *Conf) New() (PDP, error) {
	return &pdp{}, nil
}

// 実験用の pdp を実装する
type pdp struct{}

func (pdp *pdp) NotifiedOfRequest(s ac.Subject, r ac.Resource, a ac.Action) (reqctxs []ac.ReqContext, deny bool) {
	fmt.Println("pdp.NotifiedRequest start...")
	fmt.Printf("sub(%s) wants to do action(%s) on res(%s) without context\n", s.ID(), a.ID(), r.ID())
	req1 := &reqctx{"ctx-1", []string{"scope1", "scope2"}}
	req2 := &reqctx{"ctx-2", []string{"scope111", "scope2"}}
	return []ac.ReqContext{req1.toACReq(), req2.toACReq()}, false
}

func (pdp *pdp) Decision(s ac.Subject, r ac.Resource, a ac.Action, clist []ctx.Ctx) error {
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
