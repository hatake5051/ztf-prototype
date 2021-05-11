package rp1

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/gorilla/sessions"
	"github.com/hatake5051/ztf-prototype/ac"
	"github.com/hatake5051/ztf-prototype/ac/pip"
	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/ctx"
	"github.com/hatake5051/ztf-prototype/ctx/rx"
	"github.com/hatake5051/ztf-prototype/ctx/tx"
	"github.com/hatake5051/ztf-prototype/uma"
	"github.com/lestrrat-go/jwx/jwt/openid"
)

type iSessionStoreForSPIP struct {
	m sync.RWMutex
	r map[string]*s
}

var _ pip.SessionStoreForSPIP = &iSessionStoreForSPIP{}

func (sm *iSessionStoreForSPIP) Identify(session string) (ac.Subject, error) {
	sm.m.RLock()
	defer sm.m.RUnlock()
	sub, ok := sm.r[session]
	if !ok {
		return nil, fmt.Errorf("session(%s) にひもづく subject なし", session)
	}
	return sub, nil
}

func (sm *iSessionStoreForSPIP) SetIDToken(session string, idt openid.Token) error {
	sm.m.Lock()
	defer sm.m.Unlock()
	sub := &s{idt.PreferredUsername()}
	sm.r[session] = sub
	return nil
}

type iSessionStoreForCPIP struct {
	m sync.RWMutex
	r map[string]map[string]*cs // session -> capURL -> ctx.sub
	// コンテキスト送信するために必要
	spipSM          *iSessionStoreForSPIP
	store           sessions.Store
	sessionNme      string
	sessionValueKey string
}

var _ pip.SessionStoreForCPIP = &iSessionStoreForCPIP{}

func (sm *iSessionStoreForCPIP) Identify(session string, cap string) ctx.Sub {
	sm.m.Lock()
	defer sm.m.Unlock()
	v, ok := sm.r[session]
	if !ok {
		ret := &cs{
			Sub: cap + ":" + session,
		}
		if asub, err := sm.spipSM.Identify(session); err == nil {
			ret = &cs{Sub: asub.ID()}
		}
		sm.r[session] = map[string]*cs{cap: ret}
		return ret
	}
	csub, ok := v[cap]
	if !ok {
		ret := &cs{
			Sub: cap + ":" + session,
		}
		if asub, err := sm.spipSM.Identify(session); err == nil {
			ret = &cs{Sub: asub.ID()}
		}
		sm.r[session] = map[string]*cs{cap: ret}
		return ret
	}
	return csub
}

func (sm *iSessionStoreForCPIP) ForTx(capURL string) tx.SessionStore {
	return &iSessionStoreForCPIPTx{sm, capURL}
}

type iSessionStoreForCPIPTx struct {
	*iSessionStoreForCPIP
	capURL string
}

var _ tx.SessionStore = &iSessionStoreForCPIPTx{}

func (sm *iSessionStoreForCPIPTx) IdentifySubject(r *http.Request) (ctx.Sub, error) {
	session, err := sm.store.Get(r, sm.sessionNme)
	if err != nil {
		return nil, fmt.Errorf("セッションが確立していない %v", err)
	}
	v, ok := session.Values[sm.sessionValueKey]
	if !ok {
		return nil, fmt.Errorf("セッションが確立していない %v", err)
	}
	asub, err := sm.spipSM.Identify(v.(string))
	if err != nil {
		return nil, fmt.Errorf("subject の認証が終わっていない %v", err)
	}
	return newCtxSubFromAcSubject(asub), nil
}

func (sm *iSessionStoreForCPIPTx) LoadRedirectBack(r *http.Request) (redirectURL string) {
	session, err := sm.store.Get(r, sm.sessionNme)
	if err != nil {
		return ""
	}
	red, ok := session.Values[sm.capURL+"return-address"].(string)
	if !ok {
		return ""
	}
	return red
}

func (sm *iSessionStoreForCPIPTx) SetRedirectBack(r *http.Request, w http.ResponseWriter, redirectURL string) error {
	session, err := sm.store.Get(r, sm.sessionNme)
	if err != nil {
		return err
	}
	session.Values[sm.capURL+"return-address"] = redirectURL
	if err := session.Save(r, w); err != nil {
		return err
	}
	return nil
}

type iCtxDB struct {
	m       sync.RWMutex
	ctxs    map[string]map[string]*c       // sub -> ctxtype -> c
	capBase map[string]map[string][]string // cap -> ctxtype -> []ctxScope
	ctxBase map[string][]string            // ctxType -> []ctxScope
}

func (db *iCtxDB) Init(capURL string, contexts map[string][]string) {
	db.m.Lock()
	defer db.m.Unlock()
	if _, ok := db.capBase[capURL]; !ok {
		db.capBase[capURL] = make(map[string][]string)
	}
	for k, v := range contexts {
		db.capBase[capURL][k] = v
	}

	for ct, css := range contexts {
		db.ctxBase[ct] = append(db.ctxBase[ct], css...)
	}
}

var _ pip.CtxDB = &iCtxDB{}

func (db *iCtxDB) Load(sub ctx.Sub, cts []ctx.Type) ([]ctx.Ctx, error) {
	db.m.RLock()
	defer db.m.RUnlock()
	var ret []ctx.Ctx
	for _, ct := range cts {
		if v, ok := db.ctxs[sub.String()]; ok {
			if c, ok := v[ct.String()]; ok {
				ret = append(ret, c)
			}
		}
	}
	if len(ret) == 0 {
		return nil, fmt.Errorf("sub(%v) の cts(%v) は一つもない", sub, cts)
	}
	return ret, nil
}

func (db *iCtxDB) LoadAllFromCAP(capURL string, sub ctx.Sub) []ctx.Ctx {
	db.m.Lock()
	defer db.m.Unlock()
	var ctxs []ctx.Ctx
	ctxBase := db.capBase[capURL]
	for ct, css := range ctxBase {
		var c *c
		if v, ok := db.ctxs[sub.String()]; ok {
			if cc, ok := v[ct]; ok {
				c = cc
			} else {
				c = newCtxFromBase(ct, css, sub)
			}
		} else {
			c = newCtxFromBase(ct, css, sub)
		}
		ctxs = append(ctxs, c)
	}
	return ctxs
}

func (db *iCtxDB) SaveCtxFrom(e *caep.Event) error {
	db.m.Lock()
	defer db.m.Unlock()

	sub := NewCtxSubFromEventSubject(e.Subject)
	ct := ctx.NewCtxType(string(e.Type))
	var prevCtx *c
	if v, ok := db.ctxs[sub.String()]; ok {
		if prevCtx, ok = v[ct.String()]; !ok {
			prevCtx = &c{Scos: db.ctxBase[ct.String()], Values: make(map[string]string)}
		}
	} else {
		db.ctxs[sub.String()] = make(map[string]*c)
		prevCtx = &c{Scos: db.ctxBase[ct.String()], Values: make(map[string]string)}
	}

	db.ctxs[sub.String()][ct.String()] = newCtxFromEvent(e, prevCtx)
	return nil
}

func (db *iCtxDB) SaveCtxFromR(sub ctx.Sub, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("request のパースに失敗 %v", err)
	}
	ct, ok := r.Form["ctx-type"]
	if !ok {
		return fmt.Errorf("必須パラメータなし")
	}
	cv, ok := r.Form["value"]
	if !ok {
		return fmt.Errorf("答えが設定されていない")
	}
	db.m.Lock()
	defer db.m.Unlock()
	if _, ok := db.ctxs[sub.String()]; !ok {
		db.ctxs[sub.String()] = make(map[string]*c)
	}
	db.ctxs[sub.String()][ct[0]].Values[ct[0]] = cv[0]
	return nil
}

var _ rx.Translater = &iCtxDB{}

func (tr *iCtxDB) CtxSub(es *caep.EventSubject) ctx.Sub {
	return NewCtxSubFromEventSubject(es)
}

func (tr *iCtxDB) EventSubject(sub ctx.Sub) (*caep.EventSubject, error) {
	ret := &caep.EventSubject{
		User: map[string]string{
			"format": "opaque",
			"opaque": sub.Options()["sub"],
		},
	}

	if d, ok := sub.Options()["dev"]; ok {
		ret.Device = map[string]string{"format": "opaque", "opaque": d}
	}
	return ret, nil
}

func (tr *iCtxDB) CtxID(sub ctx.Sub, ct ctx.Type) (ctx.ID, error) {
	tr.m.RLock()
	defer tr.m.RUnlock()
	v, ok := tr.ctxs[sub.String()]
	if !ok {
		return nil, fmt.Errorf("tr.CtxID(%v,%v) はないよ", sub, ct)
	}
	c, ok := v[ct.String()]
	if !ok {
		return nil, fmt.Errorf("tr.CtxID(%v,%v) はないよ", sub, ct)

	}
	if c.Id != "" {
		return c.ID(), nil
	}
	return nil, fmt.Errorf("まだ sub(%v) の ct(%V) には CtxID は設定されていない", sub, ct)
}

func (tr *iCtxDB) BindCtxIDToCtx(ctxID ctx.ID, sub ctx.Sub, ct ctx.Type) error {
	tr.m.Lock()
	defer tr.m.Unlock()

	if _, ok := tr.ctxs[sub.String()]; !ok {
		tr.ctxs[sub.String()] = make(map[string]*c)
	}
	prevCtx, ok := tr.ctxs[sub.String()][ct.String()]
	if !ok {
		prevCtx = &c{Scos: tr.ctxBase[ct.String()], Values: make(map[string]string)}
	}
	tr.ctxs[sub.String()][ct.String()] = newCtxFromCtxID(ctxID, sub, ct, prevCtx)
	return nil
}

type iUMADB struct {
	m    sync.RWMutex
	pts  map[string]*uma.PermissionTicket
	rpts map[string]*uma.RPT
}

var _ rx.UMADB = &iUMADB{}

func (db *iUMADB) SetPermissionTicket(sub ctx.Sub, ticket *uma.PermissionTicket) error {
	db.m.Lock()
	defer db.m.Unlock()
	db.pts[sub.String()] = ticket
	return nil
}

func (db *iUMADB) LoadPermissionTicket(sub ctx.Sub) (*uma.PermissionTicket, error) {
	db.m.RLock()
	defer db.m.RUnlock()
	pt, ok := db.pts[sub.String()]
	if !ok {
		return nil, fmt.Errorf("sub(%v) は PermissionTicket を持っていない", sub)
	}
	return pt, nil

}
func (db *iUMADB) SetRPT(sub ctx.Sub, tok *uma.RPT) error {
	db.m.Lock()
	defer db.m.Unlock()
	db.rpts[sub.String()] = tok
	return nil
}
func (db *iUMADB) LoadRPT(sub ctx.Sub) (*uma.RPT, error) {
	db.m.RLock()
	defer db.m.RUnlock()
	tok, ok := db.rpts[sub.String()]
	if !ok {
		return nil, fmt.Errorf("sub(%v) は RPT を持っていない", sub)
	}
	return tok, nil

}
