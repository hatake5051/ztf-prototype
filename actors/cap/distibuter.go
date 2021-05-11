package cap

import (
	"fmt"

	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/ctx"
)

type distributer struct {
	*cdb
	*rxdb
	transmit func(c ctx.Ctx) error
}

func (d *distributer) SaveStatus(rxID caep.RxID, status *caep.StreamStatus) error {
	if err := d.rxdb.SaveStatus(rxID, status); err != nil {
		return err
	}

	for et := range status.EventScopes {
		ct := ctx.NewCtxType(string(et))
		sub, err := d.cdb.CtxSub(&status.Subject, rxID, ct)
		if err != nil {
			return err
		}
		c, err := d.cdb.LoadCtx(sub, ct)
		if err != nil {
			return fmt.Errorf("d.cdb.Load(%v,%v) に失敗", sub, et)
		}
		if err := d.transmit(c); err != nil {
			return fmt.Errorf("transmit に失敗 %v", err)
		}
	}
	return nil
}

func (d *distributer) SaveValue(c ctx.Ctx) error {
	if err := d.cdb.SaveValue(c); err != nil {
		return err
	}
	return d.transmit(c)
}
