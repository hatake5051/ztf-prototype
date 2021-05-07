package ctx

import (
	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/uma"
)

func NewCtxID(raw string) ID {
	return &t{raw}
}

type ID interface {
	String() string
}

func NewCtxType(raw string) Type {
	return &t{raw}
}

type Type interface {
	String() string
	UMAResType() uma.ResType
	CAEPEventType() caep.EventType
}

func NewCtxSub(raw string) Sub {
	return &t{raw}
}

type Sub interface {
	String() string
	UMAResSrv() uma.SubAtResSrv
}

func NewCtxScope(raw string) Scope {
	return &t{raw}
}

func NewCtxScopeFromCAEPEventScope(cs caep.EventScope) Scope {
	return &t{string(cs)}
}

type Scope interface {
	String() string
}

type Ctx interface {
	Type() Type
	Scopes() []Scope
	// Name は human-readble な文字列
	Name() string

	ID() ID
	Sub() Sub
	Value(Scope) string
}

type t struct {
	raw string
}

func (t *t) String() string {
	return t.raw
}

func (t *t) UMAResType() uma.ResType {
	return uma.ResType(t.raw)
}

func (t *t) CAEPEventType() caep.EventType {
	return caep.EventType(t.raw)
}

func (t *t) UMAResSrv() uma.SubAtResSrv {
	return uma.SubAtResSrv(t.raw)
}
