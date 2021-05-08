package rp

import (
	"fmt"

	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/ctx"
	"github.com/hatake5051/ztf-prototype/uma"
)

func NewCtxSub(raw string) ctx.Sub {
	return &cs{raw, ""}
}

func NewCtxSubFromEventSubject(es *caep.EventSubject) ctx.Sub {
	return &cs{es.User[es.User["format"]], es.Device[es.Device["format"]]}
}

type cs struct {
	sub string
	dev string
}

func (s *cs) String() string {
	ret := "sub:" + s.sub
	if s.dev != "" {
		ret += ":dev:" + s.dev
	}
	return ret
}

func (s *cs) UMAResSrv() uma.SubAtResSrv {
	return uma.SubAtResSrv(s.sub)
}

func (s *cs) Options() map[string]string {
	return map[string]string{"sub": s.sub, "dev": s.dev}
}

type c struct {
	typ    string
	sub    *cs
	scopes []string
	values map[string]string
	id     string
}

func newCtxFromEvent(e *caep.Event, prevCtx ctx.Ctx) c {
	es := e.Subject
	values := make(map[string]string)
	for es, v := range e.Property {
		values[string(es)] = v
	}
	var scopes []string
	for _, s := range prevCtx.Scopes() {
		scopes = append(scopes, s.String())
	}
	return c{
		typ:    string(e.Type),
		sub:    &cs{es.User[es.User["format"]], es.Device[es.Device["format"]]},
		scopes: scopes,
		values: values,
		id:     prevCtx.ID().String(),
	}
}

func newCtxFromCtxID(ctxID ctx.ID, sub ctx.Sub, ct ctx.Type, prevCtx ctx.Ctx) c {
	var scopes []string
	values := make(map[string]string)
	for _, s := range prevCtx.Scopes() {
		scopes = append(scopes, s.String())
		values[s.String()] = prevCtx.Value(s)
	}

	return c{
		typ:    ct.String(),
		sub:    &cs{sub.Options()["sub"], sub.Options()["dev"]},
		scopes: scopes,
		values: values,
		id:     prevCtx.ID().String(),
	}
}

var _ ctx.Ctx = &c{}

func (c *c) Type() ctx.Type {
	return ctx.NewCtxType(c.typ)
}

func (c *c) Scopes() []ctx.Scope {
	var ret []ctx.Scope
	for _, s := range c.scopes {
		ret = append(ret, ctx.NewCtxScope(s))
	}
	return ret
}

func (c *c) Name() string {
	return fmt.Sprintf("c:%s:s:%s", c.typ, c.sub)
}

func (c *c) ID() ctx.ID {
	return ctx.NewCtxID(c.id)
}

func (c *c) IDAtAuthZSrv() string {
	return ""
}

func (c *c) Sub() ctx.Sub {
	return c.sub
}

func (c *c) Value(s ctx.Scope) string {
	return c.values[s.String()]
}
