package rp

import (
	"fmt"
	"sync"

	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/ctx"
	"github.com/hatake5051/ztf-prototype/ctx/tx"
	"github.com/hatake5051/ztf-prototype/uma"
)

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

type iTranslaterForTx struct {
	*iCtxDB
}

var _ tx.Translater = &iTranslaterForTx{}

func (db *iTranslaterForTx) EventSubject(sub ctx.Sub, ct ctx.Type, rxID caep.RxID) (*caep.EventSubject, error) {
	db.m.RLock()
	defer db.m.RUnlock()
	c := db.ctxs[sub.String()][ct.String()]
	esub, ok := c.Subject.esubs[rxID]
	if !ok {
		return nil, fmt.Errorf("Sub(%v) の Ctx(%v) in Recv(%v) に対応する esub なし", sub, ct, rxID)
	}
	return esub, nil

}

func (db *iTranslaterForTx) ResID(ctxID ctx.ID) (uma.ResID, error) {
	db.m.RLock()
	defer db.m.RUnlock()
	for _, ctxs := range db.ctxs {
		for _, c := range ctxs {
			if c.Id == ctxID.String() {
				return uma.ResID(c.ResID), nil
			}
		}
	}
	return "", nil
}

func (db *iTranslaterForTx) BindEventSubjectToResID(rxID caep.RxID, esub *caep.EventSubject, resID uma.ResID) error {
	db.m.Lock()
	defer db.m.Unlock()
	for _, ctxs := range db.ctxs {
		for _, c := range ctxs {
			if c.ResID == string(resID) {
				c.Subject.esubs[rxID] = esub
			}

		}
	}
	return nil
}

func (db *iTranslaterForTx) BindResIDToSub(resID uma.ResID, sub ctx.Sub, ct ctx.Type) error {
	db.m.Lock()
	defer db.m.Unlock()
	cc, ok := db.ctxs[sub.String()][ct.String()]
	if !ok {
		cc = &c{Scos: db.ctxBase[ct.String()]}
	}
	db.ctxs[sub.String()][ct.String()] = newCtxFromResID(resID, sub, ct, cc)
	return nil
}
