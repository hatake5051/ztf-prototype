package cap

import (
	"fmt"
	"strings"
	"sync"

	"github.com/hatake5051/ztf-prototype/caep"
)

type ctx struct {
	ID          string
	ScopeValues map[string]string
}

type recvs struct {
	inner caep.RecvRepo
	m     sync.RWMutex
	db    map[string][]string // ctxID -> ctxID デリバーされるレシーバーID
}

func (r *recvs) Load(recvID string) (*caep.Receiver, error) {
	return r.inner.Load(recvID)
}

func (r *recvs) Save(recv *caep.Receiver) error {
	if err := r.inner.Save(recv); err != nil {
		return err
	}
	r.m.Lock()
	defer r.m.Unlock()
	for _, ctxID := range recv.StreamConf.EventsDelivered {
		r.db[ctxID] = append(r.db[ctxID], recv.ID)
	}
	return nil
}

func (r *recvs) WhereDistribution(ctxID string) []string {
	r.m.RLock()
	defer r.m.RUnlock()
	return r.db[ctxID]
}

type distributer struct {
	inner caep.SubStatusRepo
	ctxs  map[string][]string
	recvs *recvs
	tr    caep.Tr
}

func (d *distributer) RecvAndDistribute(e *caep.SSEEventClaim) {
	fmt.Printf("新しいコンテキストを受け取った %v\n", e)
	c := &ctx{
		ID:          e.ID,
		ScopeValues: e.Property,
	}
	spagID := e.Subject.SpagID
	recvers := d.recvs.WhereDistribution(e.ID)
	for _, recvID := range recvers {
		d.Ditribute(c, spagID, recvID)
	}
}

func (d *distributer) Ditribute(c *ctx, spagID, recvID string) {
	recv, err := d.recvs.Load(recvID)
	if err != nil {
		fmt.Printf("recvID(%s) に対応するレシーバがいないよ\n", recvID)
		return
	}
	aud := []caep.Receiver{*recv}
	status, err := d.inner.Load(recvID, spagID)
	if err != nil {
		fmt.Printf("recvID(%s) には spagID(%s) が登録されてないみたい\n", recvID, spagID)
		return
	}
	var scopes []string
	for ctxName, ss := range status.EventScopes {
		ctxID := ""
		for cid := range d.ctxs {
			if strings.Contains(ctxName, cid) {
				ctxID = cid
				break
			}
		}
		if ctxID == c.ID {
			scopes = ss
			break
		}
	}
	prop := make(map[string]string)
	for scope, v := range c.ScopeValues {
		for _, s := range scopes {
			if scope == s {
				prop[scope] = v
				break
			}
		}
	}

	ev := &caep.SSEEventClaim{
		ID: c.ID,
		Subject: struct {
			SubType string "json:\"subject_type\""
			SpagID  string "json:\"spag_id\""
		}{"spag", status.SpagID},
		Property: prop,
	}
	if err := d.tr.Transmit(aud, ev); err != nil {
		fmt.Printf("送信に失敗 to RecvID(%s) %v because %v\n", recvID, ev, err)
	}
}

func (d *distributer) DistributeDueToSubStatus(recvID string, status *caep.StreamStatus) {
	if status.Status != "enabled" {
		return
	}
	cm := make(map[string]ctx)
	for ctxID, scopes := range d.ctxs {
		sv := make(map[string]string)
		for _, s := range scopes {
			sv[s] = s + ":value"
		}
		cm[ctxID] = ctx{
			ID:          ctxID,
			ScopeValues: sv,
		}
	}
	recv, err := d.recvs.Load(recvID)
	if err != nil {
		fmt.Printf("recvID(%s) に対応するレシーバがいないよ\n", recvID)
		return
	}
	aud := []caep.Receiver{*recv}
	for ctxName, scopes := range status.EventScopes {
		ctxID := ""
		for cid := range d.ctxs {
			if strings.Contains(ctxName, cid) {
				ctxID = cid
				break
			}
		}
		ctx, ok := cm[ctxID]
		if !ok {
			fmt.Printf("no ctx stored in db[spagid: %s, ctxID: %s]\n", status.SpagID, ctxID)
			continue
		}
		prop := make(map[string]string)
		for scope, v := range ctx.ScopeValues {
			for _, s := range scopes {
				if scope == s {
					prop[scope] = v
					break
				}
			}
		}

		ev := &caep.SSEEventClaim{
			ID: ctx.ID,
			Subject: struct {
				SubType string "json:\"subject_type\""
				SpagID  string "json:\"spag_id\""
			}{"spag", status.SpagID},
			Property: prop,
		}
		if err := d.tr.Transmit(aud, ev); err != nil {
			fmt.Printf("送信に失敗 to RecvID(%s) %v because %v\n", recvID, ev, err)
		}
	}
}

func (d *distributer) Load(recvID, spagID string) (*caep.StreamStatus, error) {
	return d.inner.Load(recvID, spagID)
}

func (d *distributer) Save(recvID string, status *caep.StreamStatus) error {
	if err := d.inner.Save(recvID, status); err != nil {
		return err
	}
	d.DistributeDueToSubStatus(recvID, status)
	return nil
}
