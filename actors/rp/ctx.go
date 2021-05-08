package rp

import (
	"fmt"

	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/ctx"
	"github.com/hatake5051/ztf-prototype/uma"
)

func NewCtxSub(raw string) ctx.Sub {
	return &cs{raw, "", make(map[caep.RxID]*caep.EventSubject)}
}

func NewCtxSubFromEventSubject(es *caep.EventSubject) ctx.Sub {
	return &cs{es.User[es.User["format"]], es.Device[es.Device["format"]], make(map[caep.RxID]*caep.EventSubject)}
}

type cs struct {
	Sub   string
	Dev   string
	esubs map[caep.RxID]*caep.EventSubject
}

func (s *cs) String() string {
	ret := "sub:" + s.Sub
	if s.Dev != "" {
		ret += ":dev:" + s.Dev
	}
	return ret
}

func (s *cs) UMAResSrv() uma.SubAtResSrv {
	return uma.SubAtResSrv(s.Sub)
}

func (s *cs) Options() map[string]string {
	return map[string]string{"sub": s.Sub, "dev": s.Dev}
}

type c struct {
	Typ     string
	Subject *cs
	Scos    []string
	Values  map[string]string
	Id      string
	ResID   string
}

func newCtxFromEvent(e *caep.Event, prevCtx *c) *c {
	es := e.Subject
	values := make(map[string]string)
	for es, v := range e.Property {
		values[string(es)] = v
	}

	return &c{
		Typ:     string(e.Type),
		Subject: &cs{es.User[es.User["format"]], es.Device[es.Device["format"]], make(map[caep.RxID]*caep.EventSubject)},
		Scos:    prevCtx.Scos,
		Values:  values,
		Id:      prevCtx.Id,
	}
}

func newCtxFromCtxID(ctxID ctx.ID, sub ctx.Sub, ct ctx.Type, prevCtx *c) *c {
	var scopes []string
	values := make(map[string]string)
	for _, s := range prevCtx.Scopes() {
		scopes = append(scopes, s.String())
		values[s.String()] = prevCtx.Value(s)
	}

	return &c{
		Typ:     ct.String(),
		Subject: &cs{sub.Options()["sub"], sub.Options()["dev"], make(map[caep.RxID]*caep.EventSubject)},
		Scos:    scopes,
		Values:  values,
		Id:      ctxID.String(),
	}
}

func newCtxFromResID(resID uma.ResID, sub ctx.Sub, ct ctx.Type, prevCtx *c) *c {
	var scopes []string
	values := make(map[string]string)
	for _, s := range prevCtx.Scopes() {
		scopes = append(scopes, s.String())
		values[s.String()] = prevCtx.Value(s)
	}

	return &c{
		Typ:     ct.String(),
		Subject: &cs{sub.Options()["sub"], sub.Options()["dev"], make(map[caep.RxID]*caep.EventSubject)},
		Scos:    scopes,
		Values:  values,
		ResID:   string(resID),
	}
}

var _ ctx.Ctx = &c{}

func (c *c) Type() ctx.Type {
	return ctx.NewCtxType(c.Typ)
}

func (c *c) Scopes() []ctx.Scope {
	var ret []ctx.Scope
	for _, s := range c.Scos {
		ret = append(ret, ctx.NewCtxScope(s))
	}
	return ret
}

func (c *c) Name() string {
	return fmt.Sprintf("c:%s:s:%s", c.Typ, c.Subject)
}

func (c *c) ID() ctx.ID {
	return ctx.NewCtxID(c.Id)
}

func (c *c) IDAtAuthZSrv() string {
	return ""
}

func (c *c) Sub() ctx.Sub {
	return c.Subject
}

func (c *c) Value(s ctx.Scope) string {
	return c.Values[s.String()]
}
