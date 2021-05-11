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

var _ ctx.Sub = &s{}

func (s *s) String() string {
	return s.sub
}

func (s *s) UMAResSrv() uma.SubAtResSrv {
	return uma.SubAtResSrv(s.sub)
}

func (s *s) Options() map[string]string {
	return map[string]string{"sub": s.sub}
}

type c struct {
	typ    string
	sub    *s
	scopes []string
	values map[string]string
	resID  uma.ResID
	id     string
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
	return ctx.NewCtxID(c.id) //fmt.Sprintf("id:c:%s:s:%s", c.typ, c.sub)
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
	rpBase map[string][]string // rpURL -> []ctx.Type
	cBase  map[string]c        // ctx.Type -> ctx.Ctx
	m      sync.RWMutex
	ctxs   map[string]map[string]*c // subject -> ctx.Type -> ctx.Ctx
	subs   map[string]*s            // ( pseudonymou )ctx.Sub -> (cap-identifiable) subject
}

var _ tx.CtxDB = &cdb{}

func (db *cdb) LoadCtx(sub ctx.Sub, ct ctx.Type) (ctx.Ctx, error) {
	db.m.RLock()
	defer db.m.RUnlock()
	if v, ok := db.ctxs[sub.String()]; ok {
		if c, ok := v[ct.String()]; ok {
			return c, nil
		}
	}
	c := db.cBase[ct.String()]
	c.sub = &s{
		sub.String(), make(map[caep.RxID]caep.EventSubject),
	}
	return &c, nil
}

func (db *cdb) LoadAll(sub ctx.Sub) ([]ctx.Ctx, error) {
	db.m.RLock()
	defer db.m.RUnlock()
	var ans []ctx.Ctx
	for ct, cv := range db.cBase {
		if v, ok := db.ctxs[sub.String()]; ok {
			if c, ok := v[ct]; ok {
				ans = append(ans, c)
				continue
			}
		}
		s := &s{sub.String(), make(map[caep.RxID]caep.EventSubject)}
		ans = append(ans, &c{
			cv.typ, s, cv.scopes, make(map[string]string), "", fmt.Sprintf("id:c:%s:s:%s", cv.typ, s.String()),
		})
	}
	return ans, nil
}

func (db *cdb) SaveValue(ct ctx.Ctx) error {
	db.m.Lock()
	defer db.m.Unlock()
	ss := db.subs[ct.Sub().String()]
	if _, ok := db.ctxs[ss.String()]; !ok {
		db.ctxs[ss.String()] = make(map[string]*c)
	}
	prev, ok := db.ctxs[ss.String()][ct.Type().String()]
	ccc := db.cBase[ct.Type().String()]
	if !ok {
		ccc.sub = ss
		ccc.id = fmt.Sprintf("id:c:%s:s:%s", ccc.typ, ss.String())
		ccc.resID = ""
		ccc.values = make(map[string]string)
		for _, scop := range ccc.scopes {
			ccc.values[scop] = ct.Value(ctx.NewCtxScope(scop))
		}
		db.ctxs[ss.String()][ct.Type().String()] = &ccc
		return nil
	}
	for _, scop := range ccc.scopes {
		newv := ct.Value(ctx.NewCtxScope(scop))
		if newv != "" {
			prev.values[scop] = newv
		}
	}
	db.ctxs[ss.String()][ct.Type().String()] = prev
	return nil
}

var _ tx.Translater = &cdb{}

func (db *cdb) EventSubject(sub ctx.Sub, ct ctx.Type, rxID caep.RxID) (*caep.EventSubject, error) {
	db.m.RLock()
	defer db.m.RUnlock()
	ss := db.subs[sub.String()]
	if v, ok := db.ctxs[ss.String()]; ok {
		if c, ok := v[ct.String()]; ok {
			if esub, ok := c.sub.esubs[rxID]; ok {
				return &esub, nil
			}
		}
	}
	return nil, fmt.Errorf("cdb.EventSub(%v,%v, %v) でコンテキストが見つからなかった", sub, ct, rxID)
}

func (db *cdb) CtxSub(esub *caep.EventSubject, rxID caep.RxID) (ctx.Sub, error) {
	db.m.RLock()
	defer db.m.RUnlock()
	ss, ok := db.subs[esub.Identifier()]
	if !ok {
		return nil, fmt.Errorf("db.subs から esub(%v) に対応するもの見つからん ", esub)
	}
	return ss, nil
}

func (db *cdb) ResID(cid ctx.ID) (uma.ResID, error) {
	db.m.Lock()
	defer db.m.Unlock()
	for _, v := range db.ctxs {
		if v != nil {
			for _, c := range v {
				if c.id == cid.String() {
					if string(c.resID) != "" {
						return c.resID, nil
					}
				}
			}
		}
	}
	return "", fmt.Errorf("cdb.ResID(%v) は見つからない", cid)
}

func (db *cdb) BindEventSubjectToResID(rxID caep.RxID, esub *caep.EventSubject, resID uma.ResID) error {
	db.m.Lock()
	defer db.m.Unlock()
	for _, v := range db.ctxs {
		if v != nil {
			for _, c := range v {
				if string(c.resID) == string(resID) {
					c.sub.esubs[rxID] = *esub
					db.subs[esub.Identifier()] = c.sub
					return nil
				}
			}
		}
	}
	return fmt.Errorf("cdb.BindEventSubjectToResID(%v,%v,%v) に失敗", rxID, esub, resID)
}

func (db *cdb) BindResIDToSub(resID uma.ResID, csub ctx.Sub, ct ctx.Type) error {
	db.m.Lock()
	defer db.m.Unlock()
	ss := db.subs[csub.String()]
	if v, ok := db.ctxs[ss.String()]; ok {
		if c, ok := v[ct.String()]; ok {
			c.resID = resID
			return nil
		}
	} else {
		db.ctxs[ss.String()] = make(map[string]*c)
	}
	base := db.cBase[ct.String()]
	base.resID = resID
	base.sub = ss
	base.id = fmt.Sprintf("id:c:%s:s:%s", ct.String(), ss.String())
	db.ctxs[ss.String()][ct.String()] = &base
	return nil
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
