package cap

import (
	"fmt"
	"sync"

	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/uma"
)

type CtxDBForDistributer interface {
	Value(SubAtCAP, CtxType, CtxScope) (string, error)
	Update(SubAtCAP, CtxType, CtxScope, string) error
}

type SubPIDTranslater interface {
	Identify(*caep.EventSubject, caep.RxID) (SubAtCAP, error)
	Translate(SubAtCAP, caep.RxID) (*caep.EventSubject, error)
	SaveResID(SubAtCAP, uma.ResID) error
	BindResIDToPID(uma.ResID, caep.RxID, *caep.EventSubject) error
}

type distributer struct {
	inner caep.SubStatusRepo
	recvs *recvs
	tr    caep.Tx
	ctxs  CtxDBForDistributer
	pid   SubPIDTranslater
}

var _ caep.SubStatusRepo = &distributer{}

func (d *distributer) Load(rxID caep.RxID, sub *caep.EventSubject) (*caep.StreamStatus, error) {
	return d.inner.Load(rxID, sub)
}

func (d *distributer) Save(rxID caep.RxID, status *caep.StreamStatus) error {
	if err := d.inner.Save(rxID, status); err != nil {
		return err
	}
	d.DistributeBasedOnSubStatus(status, rxID)
	return nil
}

func (d *distributer) Ditribute(c Ctx, rxID caep.RxID) {
	recv, err := d.recvs.Load(rxID)
	if err != nil {
		fmt.Printf("recvID(%s) に対応するレシーバがいないよ\n", rxID)
		return
	}
	aud := []caep.Receiver{*recv}
	sub, err := d.pid.Translate(c.Sub(), rxID)
	if err != nil {
		fmt.Printf("Receiver(%v) は sub(%v) の pid を持っていない", rxID, c.Sub())
	}
	status, err := d.inner.Load(rxID, sub)
	if err != nil {
		fmt.Printf("Receiver(%s) には sub(%v) が登録されてないみたい\n", rxID, sub)
		return
	}
	if status.Status != "enabled" {
		return
	}
	authorizedScopes := status.EventScopes[c.Type().CAEPEventType()]
	prop := make(map[caep.EventScope]string)
	for _, scope := range authorizedScopes {
		prop[scope] = c.Value(NewCtxScopeFromCAEPEventScope(scope))
	}

	ev := &caep.Event{
		Type:     c.Type().CAEPEventType(),
		Subject:  sub,
		Property: prop,
	}
	if err := d.tr.Transmit(aud, ev); err != nil {
		fmt.Printf("送信に失敗 to Rx(%s) %v because %v\n", rxID, ev, err)
	}
}

func (d *distributer) DistributeBasedOnSubStatus(status *caep.StreamStatus, rxID caep.RxID) {
	recv, err := d.recvs.Load(rxID)
	if err != nil {
		fmt.Printf("recvID(%s) に対応するレシーバがいないよ\n", rxID)
		return
	}
	aud := []caep.Receiver{*recv}

	if status.Status != "enabled" {
		return
	}
	sub, err := d.pid.Identify(&status.Subject, rxID)
	if err != nil {
		fmt.Printf("status(%v) に対応する subatcap がいない\n", status)
	}
	for et, ess := range status.EventScopes {
		ct := NewCtxTypeFromCAEPEventType(et)
		prop := make(map[caep.EventScope]string)
		for _, es := range ess {
			v, err := d.ctxs.Value(sub, ct, NewCtxScopeFromCAEPEventScope(es))
			if err != nil {
				fmt.Printf("送信に失敗だとお\n")
				continue
			}
			prop[es] = v
		}
		ev := &caep.Event{
			Type:     et,
			Subject:  &status.Subject,
			Property: prop,
		}
		if err := d.tr.Transmit(aud, ev); err != nil {
			fmt.Printf("送信に失敗 to Rx(%s) %v because %v\n", rxID, ev, err)
		}
	}
}

// recv は caep.RxRepo を満たすものであり、
// 配送する際にどのコンテキストを誰に送るかを記憶しておくためのラッパー
type recvs struct {
	inner caep.RxRepo
	m     sync.RWMutex
	db    map[CtxType][]caep.RxID // ctxType ->  デリバーされるレシーバーID
}

var _ caep.RxRepo = &recvs{}

func (r *recvs) Load(rxID caep.RxID) (*caep.Receiver, error) {
	return r.inner.Load(rxID)
}

func (r *recvs) Save(recv *caep.Receiver) error {
	if err := r.inner.Save(recv); err != nil {
		return err
	}
	r.m.Lock()
	defer r.m.Unlock()
	for _, eType := range recv.StreamConf.EventsDelivered {
		r.db[CtxType(eType)] = append(r.db[CtxType(eType)], recv.ID)
	}
	return nil
}

func (r *recvs) WhereDistribution(ct CtxType) []caep.RxID {
	r.m.RLock()
	defer r.m.RUnlock()
	return r.db[ct]
}
