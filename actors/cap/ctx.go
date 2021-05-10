package cap

import (
	"fmt"
	"sync"

	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/ctx"
	"github.com/hatake5051/ztf-prototype/ctx/tx"
	"github.com/hatake5051/ztf-prototype/uma"
)

func NewCtxSub(raw string) ctx.Sub {
	return &s{raw, make(map[caep.RxID]caep.EventSubject)}
}

type s struct {
	sub   string
	esubs map[caep.RxID]caep.EventSubject
}

func (s *s) String() string {
	return s.sub
}

func (s *s) UMAResSrv() uma.SubAtResSrv {
	return uma.SubAtResSrv(s.sub)
}

func (s *s) Options() map[string]string {
	return make(map[string]string)
}

type c struct {
	typ    string
	sub    *s
	scopes []string
	values map[string]string
	resID  uma.ResID
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
	return ctx.NewCtxID(fmt.Sprintf("id:c:%s:s:%s", c.typ, c.sub))
}

func (c *c) IDAtAuthZSrv() string {
	return string(c.resID)
}

func (c *c) Sub() ctx.Sub {
	return c.sub
}

func (c *c) Value(s ctx.Scope) string {
	return c.values[s.String()]
}

type cdb struct {
	cBase map[string]c // ctx.Type -> ctx.Ctx
	m     sync.Mutex
	// めんどいので
	d []*c
}

var _ tx.CtxDB = &cdb{}

func (db *cdb) LoadCtx(sub ctx.Sub, ct ctx.Type) (ctx.Ctx, error) {
	db.m.Lock()
	defer db.m.Unlock()
	for _, c := range db.d {
		if c.Sub().String() == sub.String() && c.Type().String() == ct.String() {
			return c, nil
		}
	}
	c := db.cBase[ct.String()]
	c.sub = &s{
		sub.String(), make(map[caep.RxID]caep.EventSubject),
	}
	db.d = append(db.d, &c)
	return &c, nil
}

func (db *cdb) LoadAll(sub ctx.Sub) ([]ctx.Ctx, error) {
	db.m.Lock()
	defer db.m.Unlock()
	var ans []ctx.Ctx
	for _, c := range db.d {
		if c.Sub().String() == sub.String() {
			ans = append(ans, c)
		}
	}
	if len(ans) != len(db.cBase) {
		for ct, cv := range db.cBase {
			exits := false
			for _, a := range ans {
				if a.Type().String() == ct {
					exits = true
					break
				}
			}
			if !exits {
				ans = append(ans, &c{
					sub:    &s{sub.String(), make(map[caep.RxID]caep.EventSubject)},
					typ:    cv.typ,
					scopes: cv.scopes,
					values: make(map[string]string),
				})
			}
		}
		return ans, nil
	}
	return ans, nil
}

func (db *cdb) SaveValue(c ctx.Ctx) error {
	db.m.Lock()
	defer db.m.Unlock()
	for _, prev := range db.d {
		if prev.ID().String() == c.ID().String() {
			for k, _ := range prev.values {
				newv := c.Value(ctx.NewCtxScope(k))
				if newv != "" {
					prev.values[k] = newv
				}
			}
		}
	}
	return nil
}

var _ tx.Translater = &cdb{}

func (db *cdb) EventSubject(sub ctx.Sub, ct ctx.Type, rxID caep.RxID) (*caep.EventSubject, error) {
	db.m.Lock()
	defer db.m.Unlock()
	for _, c := range db.d {
		if c.Sub().String() == sub.String() {
			esub, ok := c.sub.esubs[rxID]
			if !ok {
				return nil, fmt.Errorf("cdb.EventSub(%v,%v) で%v から sub.esub から見つからなかった", sub, rxID, c)
			}
			return &esub, nil
		}
	}
	return nil, fmt.Errorf("cdb.EventSub(%v,%v) でコンテキストが見つからなかった", sub, rxID)
}

func (db *cdb) CtxSub(esub *caep.EventSubject, rxID caep.RxID) (ctx.Sub, error) {
	db.m.Lock()
	defer db.m.Unlock()
	for _, c := range db.d {
		if es, ok := c.sub.esubs[rxID]; ok && es.Identifier() == esub.Identifier() {
			return c.sub, nil
		}
	}
	return nil, fmt.Errorf("cdb.CtxSub(%v,%v) で失敗", esub, rxID)
}

func (db *cdb) ResID(cid ctx.ID) (uma.ResID, error) {
	db.m.Lock()
	defer db.m.Unlock()
	for _, c := range db.d {
		if c.ID().String() == cid.String() {
			return uma.ResID(c.resID), nil
		}
	}
	return "", fmt.Errorf("cdb.ResID(%v) は見つからない", cid)
}

func (db *cdb) BindEventSubjectToResID(rxID caep.RxID, esub *caep.EventSubject, resID uma.ResID) error {
	db.m.Lock()
	defer db.m.Unlock()
	for _, c := range db.d {
		if c.resID == resID {
			c.sub.esubs[rxID] = *esub
			return nil
		}
	}
	return fmt.Errorf("cdb.BindEventSubjectToResID(%v,%v,%v) に失敗", rxID, esub, resID)
}

func (db *cdb) BindResIDToSub(resID uma.ResID, csub ctx.Sub, ct ctx.Type) error {
	db.m.Lock()
	defer db.m.Unlock()
	for _, c := range db.d {
		if c.Sub().String() == csub.String() && c.Type().String() == ct.String() {
			c.resID = resID
			return nil
		}
	}
	return fmt.Errorf("cdb.BindResIDToSub(%v,%v,%v) に失敗", resID, csub, ct)
}

type rxdb struct {
	db1, db2, db3 sync.Map
}

var _ tx.RxDB = &rxdb{}

func (db *rxdb) Load(rxID caep.RxID) (*caep.Receiver, error) {
	v, ok := db.db1.Load(rxID)
	if !ok {
		return nil, fmt.Errorf("rxdbLoad(%v) に失敗", rxID)
	}
	return v.(*caep.Receiver), nil
}

func (db *rxdb) Save(recv *caep.Receiver) error {
	db.db1.Store(recv.ID, recv)
	return nil
}

func (db *rxdb) Auds(ct ctx.Type) ([]caep.Receiver, error) {
	rxIDs, ok := db.db3.Load(ct.String())
	if !ok {
		return nil, fmt.Errorf("rxdb.Aud(%v) に失敗", ct)
	}
	var ret []caep.Receiver
	for _, rxID := range rxIDs.([]caep.RxID) {
		recv, err := db.Load(rxID)
		if err != nil {
			return nil, err
		}
		ret = append(ret, *recv)
	}
	return ret, nil
}

func (db *rxdb) LoadStatus(rxID caep.RxID, sub *caep.EventSubject) (*caep.StreamStatus, error) {
	key := fmt.Sprintf("%s:%s", rxID, sub.Identifier())
	v, ok := db.db2.Load(key)
	if !ok {
		return nil, fmt.Errorf("rxdb.LoadStatus(%s,%s) に失敗", rxID, sub)
	}
	return v.(*caep.StreamStatus), nil
}

func (db *rxdb) SaveStatus(rxID caep.RxID, status *caep.StreamStatus) error {
	key := fmt.Sprintf("%s:%s", rxID, status.Subject.Identifier())
	db.db2.Store(key, status)

	for et, _ := range status.EventScopes {
		var vv []caep.RxID
		if v, ok := db.db3.Load(string(et)); ok {
			vv = v.([]caep.RxID)
		}
		vv = append(vv, rxID)
		db.db3.Store(string(et), vv)
	}
	return nil
}
