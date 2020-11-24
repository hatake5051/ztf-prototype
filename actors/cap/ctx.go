package cap

import (
	"fmt"
	"strings"

	"github.com/hatake5051/ztf-prototype/caep"
)

type ctx struct {
	ID          string
	ScopeValues map[string]string
}

type distributer struct {
	inner caep.SubStatusRepo
	ctxs  map[string][]string
	recvs caep.RecvRepo
	tr    caep.Tr
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
