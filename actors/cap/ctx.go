package cap

import (
	"fmt"
	"sync"

	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/uma"
)

// CtxType はコンテキストのクラスを表現する
type CtxType string

// UMAResType は ctxType を uma.ResType に適合させる
func (t CtxType) UMAResType() uma.ResType {
	return uma.ResType(t)
}

func NewCtxTypeFromCAEPEventType(et caep.EventType) CtxType {
	return CtxType(et)
}

func (t CtxType) CAEPEventType() caep.EventType {
	return caep.EventType(t)
}

// CtxScope はコンテキストのスコープを表現する
type CtxScope string

func NewCtxScopeFromCAEPEventScope(es caep.EventScope) CtxScope {
	return CtxScope(es)
}

type Ctx interface {
	Type() CtxType
	Scopes() []CtxScope
	// Name は human-readble な文字列
	Name() string

	Value(CtxScope) string
	Sub() SubAtCAP
	// TODO: AUthZSrv が複数ある場合
	IDAtAuthZSrv() uma.ResID
}

type ctx struct {
	t           CtxType
	scopes      []CtxScope
	sub         SubAtCAP
	scopeValues map[CtxScope]string
	resID       uma.ResID
}

var _ Ctx = &ctx{}

func (c *ctx) Type() CtxType {
	return c.t
}

func (c *ctx) Scopes() []CtxScope {
	return c.scopes
}

func (c *ctx) Name() string {
	return fmt.Sprintf("ctx:%s:sub:%s", c.t, c.sub)
}

func (c *ctx) Value(cs CtxScope) string {
	return c.scopeValues[cs]
}

func (c *ctx) Sub() SubAtCAP {
	return c.sub
}

func (c *ctx) IDAtAuthZSrv() uma.ResID {
	return c.resID
}

type ctxDB struct {
	all     []CtxType       // all ctxTypes
	ctxBase map[CtxType]ctx // ctxType -> ctx のベース
	db      sync.Map        // ctxType + sub -> ctx
	pid     SubPIDTranslater
}

var _ CtxDB = &ctxDB{}

func (db *ctxDB) Load(sub SubAtCAP, ct CtxType) (Ctx, error) {
	key := fmt.Sprintf("ctx:%s:sub:%s", ct, sub)
	v, ok := db.db.Load(key)
	fmt.Printf("Loaded %#v\n", v)
	if !ok {
		ctx := db.ctxBase[ct]
		ctx.sub = sub
		db.db.Store(key, ctx)
		return &ctx, nil
	}
	c, ok := v.(ctx)
	if !ok {
		return nil, fmt.Errorf("invalid")
	}
	return &c, nil
}

func (db *ctxDB) SaveIDAtAuthZSrv(sub SubAtCAP, ct CtxType, idAtAuthZSrv uma.ResID) error {
	key := fmt.Sprintf("ctx:%s:sub:%s", ct, sub)
	v, ok := db.db.Load(key)
	if !ok {
		return fmt.Errorf("not found")
	}
	c, ok := v.(ctx)
	if !ok {
		return fmt.Errorf("not found")
	}
	c.resID = idAtAuthZSrv
	fmt.Printf("aaa %#v\n", c)
	db.db.Store(key, c)
	if err := db.pid.SaveResID(sub, idAtAuthZSrv); err != nil {
		return err
	}
	return nil
}

func (db *ctxDB) All() []CtxType {
	return db.all
}

func (db *ctxDB) Value(sub SubAtCAP, ct CtxType, cs CtxScope) (string, error) {
	key := fmt.Sprintf("ctx:%s:sub:%s", ct, sub)
	v, ok := db.db.Load(key)
	if !ok {
		return "", fmt.Errorf("Sub(%s) のコンテキスト(%s)を管理していない", sub, ct)
	}
	c := v.(ctx)
	return c.scopeValues[cs], nil
}

func (db *ctxDB) Update(sub SubAtCAP, ct CtxType, cs CtxScope, v string) error {
	key := fmt.Sprintf("ctx:%s:sub:%s", ct, sub)
	vv, ok := db.db.Load(key)
	if !ok {
		return fmt.Errorf("Sub(%s) のコンテキスト(%s)を管理していない", sub, ct)
	}
	c := vv.(ctx)
	c.scopeValues[cs] = v
	db.db.Store(key, c)
	return nil
}
