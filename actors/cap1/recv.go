package cap1

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/ctx"
	"github.com/hatake5051/ztf-prototype/ctx/rx"
	"github.com/hatake5051/ztf-prototype/uma"
)

type recvConf map[string]rx.Conf

func (conf *recvConf) new(d *distributer) *recv {
	dummyreqs := map[string][]rx.ReqCtx{
		"rp1": {
			rx.ReqCtx{
				Type:   ctx.NewCtxType("ip"),
				Scopes: []ctx.Scope{ctx.NewCtxScope("raw")},
			},
		},
	}
	return &recv{distributer: d, conf: *conf, reqs: dummyreqs}
}

type recv struct {
	reqs  map[string][]rx.ReqCtx
	alist sync.Map
	conf  recvConf
	*distributer
}

func (r *recv) SaveStatus(rxID caep.RxID, status *caep.StreamStatus) error {
	if err := r.distributer.SaveStatus(rxID, status); err != nil {
		return err
	}
	sub := r.cdb.subs[status.Subject.Identifier()]
	rxID2rpURL := map[caep.RxID]string{
		caep.RxID("rp1"): "http://rp1.ztf-proto.k3.ipv6.mobi",
		caep.RxID("rp2"): "http://rp2.ztf-proto.k3.ipv6.mobi",
	}
	return r.addSub(rxID2rpURL[rxID], sub, r.reqs[string(rxID)])
}

func (recv *recv) agent(rpURL string) rx.Rx {
	v, ok := recv.alist.Load(rpURL)
	if ok {
		return v.(rx.Rx)
	}
	rxconf, ok := recv.conf[rpURL]
	if !ok {
		panic(fmt.Sprintf("%s の agent はコンフィグにない", rpURL))
	}
	u := &iUMADB{sync.RWMutex{}, make(map[string]*uma.PermissionTicket), make(map[string]*uma.RPT)}
	rx := rxconf.New(&ctxDBForRx{recv.distributer}, u, &translaterForRx{recv.distributer})
	recv.alist.Store(rpURL, rx)
	return rx
}

func (recv *recv) addSub(rpURL string, sub ctx.Sub, reqs []rx.ReqCtx) error {
	a := recv.agent(rpURL)
	if err := a.AddSub(sub, reqs); err != nil {
		if err, ok := err.(*uma.ReqRPTError); ok {
			return newE(err, SubjectForCtxUnAuthorizeButReqSubmitted)
		}
		return newEO(err, CtxIDNotRegistered, rpURL)
	}
	return nil
}

func (recv *recv) SetCtxID(rpURL string, sub ctx.Sub, ctxType, ctxID string) error {
	a := recv.agent(rpURL)
	return a.RegisterCtxID(sub, ctx.NewCtxType(ctxType), ctx.NewCtxID(ctxID))
}

func (recv *recv) MnagedCtxList(rpURL string, sub ctx.Sub) []ctx.Ctx {
	recv.m.Lock()
	defer recv.m.Unlock()
	var ret []ctx.Ctx
	ss := recv.subs[sub.String()]
	for _, ctstr := range recv.cdb.rpBase[rpURL] {
		ct := ctx.NewCtxType(ctstr)
		if v, ok := recv.cdb.ctxs[ss.String()]; ok {
			if c, ok := v[ct.String()]; ok {
				ret = append(ret, c)
				continue
			}
		}
		tmp := recv.cdb.cBase[ct.String()]
		tmp.sub = ss
		ret = append(ret, &tmp)
	}
	return ret
}

func (recv *recv) RecvCtx(rpURL string, r *http.Request) error {
	a := recv.agent(rpURL)
	return a.RecvCtx(r)
}

// ErrorCode は PIP で発生したエラー情報を伝える
type ErrorCode int

const (
	// CtxIDNotRegistered は Context の CtxID が設定されていないことを表す。
	// Option() として登録すべき cap-host string を返す。
	CtxIDNotRegistered = iota + 1
	// SubjectForCtxUnAuthorizeButReqSubmitted はUMA Authz process で res owner の許可待ち状態であることを表す
	SubjectForCtxUnAuthorizeButReqSubmitted
	// CtxsNotFound は ctx をまだ rp が所持していないことを表す(CAPからもらう認可は下りているが、まだCAP からもらっていないとか)
	CtxsNotFound
)

// e implements pip.Error
type e struct {
	error
	code ErrorCode
	opt  interface{}
}

func (e *e) Code() ErrorCode {
	return e.code
}

func (e *e) Option() interface{} {
	return e.opt
}

func newE(err error, code ErrorCode) *e {
	return &e{err, code, nil}
}
func newEO(err error, code ErrorCode, opt interface{}) *e {
	return &e{err, code, opt}
}

// Error は PIP で発生した外部で処理すべきエラー
type Error interface {
	error
	Code() ErrorCode
	Option() interface{}
}

type ctxDBForRx struct{ *distributer }

var _ rx.CtxDB = &ctxDBForRx{}

func (db *ctxDBForRx) SaveCtxFrom(e *caep.Event) error {
	db.m.Lock()
	defer db.m.Unlock()
	sub := db.subs[e.Subject.Identifier()]
	ct := ctx.NewCtxType((string(e.Type)))
	var prevCtx *c
	if v, ok := db.ctxs[sub.String()]; ok {
		prevCtx, ok = v[ct.String()]
		if !ok {
			tmp := db.cBase[ct.String()]
			prevCtx = &tmp
			prevCtx.sub = sub
		}
	} else {
		db.ctxs[sub.String()] = make(map[string]*c)
		tmp := db.cBase[ct.String()]
		prevCtx = &tmp
		prevCtx.sub = sub
	}
	for sc, v := range e.Property {
		prevCtx.values[string(sc)] = v
	}
	db.ctxs[sub.String()][ct.String()] = prevCtx
	return nil
}

type translaterForRx struct{ *distributer }

var _ rx.Translater = &translaterForRx{}

func (tr *translaterForRx) CtxSub(esub *caep.EventSubject) ctx.Sub {
	tr.m.RLock()
	defer tr.m.RUnlock()
	return tr.subs[esub.Identifier()]
}

func (tr *translaterForRx) EventSubject(csub ctx.Sub) (*caep.EventSubject, error) {
	tr.m.Lock()
	defer tr.m.Unlock()
	ret := &caep.EventSubject{
		User: map[string]string{
			"format": "opaque",
			"opaque": csub.Options()["sub"],
		},
	}

	if d, ok := csub.Options()["dev"]; ok {
		ret.Device = map[string]string{"format": "opaque", "opaque": d}
	}
	sub := tr.subs[csub.String()]
	tr.subs[ret.Identifier()] = sub
	return ret, nil
}

func (tr *translaterForRx) CtxID(sub ctx.Sub, ct ctx.Type) (ctx.ID, error) {
	tr.m.RLock()
	defer tr.m.RUnlock()
	s := tr.subs[sub.String()]
	v, ok := tr.ctxs[s.String()]
	if !ok {
		return nil, fmt.Errorf("tr.CtxID(%v,%v) はないよ", sub, ct)
	}
	c, ok := v[ct.String()]
	if !ok {
		return nil, fmt.Errorf("tr.CtxID(%v,%v) はないよ", sub, ct)

	}
	if c.id != "" {
		return c.ID(), nil
	}
	return nil, fmt.Errorf("まだ sub(%v) の ct(%V) には CtxID は設定されていない", sub, ct)
}

func (tr *translaterForRx) BindCtxIDToCtx(ctxID ctx.ID, sub ctx.Sub, ct ctx.Type) error {
	tr.m.Lock()
	defer tr.m.Unlock()
	s := tr.subs[sub.String()]
	if _, ok := tr.ctxs[s.String()]; !ok {
		tr.ctxs[sub.String()] = make(map[string]*c)
	}
	prevCtx, ok := tr.ctxs[s.String()][ct.String()]
	if !ok {
		tmp := tr.cBase[ct.String()]
		prevCtx = &tmp
		prevCtx.sub = s

	}
	prevCtx.id = ctxID.String()
	tr.ctxs[s.String()][ct.String()] = prevCtx
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
