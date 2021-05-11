package rp1

import (
	"fmt"

	"github.com/hatake5051/ztf-prototype/ac"
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

func newCtxSubFromAcSubject(asub ac.Subject) ctx.Sub {
	return &cs{asub.ID(), "", make(map[caep.RxID]*caep.EventSubject)}
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

func newCtxFromBase(ctxType string, ctxScopes []string, sub ctx.Sub) *c {
	return &c{
		ctxType,
		&cs{sub.Options()["sub"], sub.Options()["dev"], make(map[caep.RxID]*caep.EventSubject)},
		ctxScopes,
		make(map[string]string),
		fmt.Sprintf("id:c:%s:s:%s", ctxType, sub.String()),
		"",
	}
}

func newCtxFromEvent(e *caep.Event, prevCtx *c) *c {
	es := e.Subject
	values := make(map[string]string)
	for es, v := range e.Property {
		values[string(es)] = v
	}

	return &c{
		string(e.Type),
		&cs{es.User[es.User["format"]], es.Device[es.Device["format"]], make(map[caep.RxID]*caep.EventSubject)},
		prevCtx.Scos,
		values,
		prevCtx.Id,
		prevCtx.ResID,
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
		ct.String(),
		&cs{sub.Options()["sub"], sub.Options()["dev"], make(map[caep.RxID]*caep.EventSubject)},
		scopes,
		values,
		ctxID.String(),
		prevCtx.ResID,
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
		ct.String(),
		&cs{sub.Options()["sub"], sub.Options()["dev"], make(map[caep.RxID]*caep.EventSubject)},
		scopes,
		values,
		prevCtx.Id,
		string(resID),
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
	return c.ResID
}

func (c *c) Sub() ctx.Sub {
	return c.Subject
}

func (c *c) Value(s ctx.Scope) string {
	return c.Values[s.String()]
}
