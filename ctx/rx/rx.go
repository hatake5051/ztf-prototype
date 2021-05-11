package rx

import (
	"fmt"
	"net/http"

	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/ctx"
	"github.com/hatake5051/ztf-prototype/uma"
)

func (conf *Conf) New(ctxDB CtxDB, umaDB UMADB, translater Translater) Rx {
	u, err := conf.UMA.new(umaDB)
	if err != nil {
		panic("UMACLINT の生成に失敗 " + err.Error())
	}

	c, err := conf.CAEP.new(conf.UMA.to(), u, translater.CtxSub)
	if err != nil {
		panic("CAEPRECV の生成に失敗" + err.Error())
	}
	return &rx{c, u, ctxDB, translater}
}

type Rx interface {
	RegisterCtxID(ctx.Sub, ctx.Type, ctx.ID) error
	RecvCtx(*http.Request) error
	AddSub(ctx.Sub, []ReqCtx) error
}

type ReqCtx struct {
	Type   ctx.Type
	Scopes []ctx.Scope
}

type CtxDB interface {
	SaveCtxFrom(*caep.Event) error
}

type Translater interface {
	CtxSub(*caep.EventSubject) ctx.Sub
	EventSubject(ctx.Sub) (*caep.EventSubject, error)
	CtxID(ctx.Sub, ctx.Type) (ctx.ID, error)
	BindCtxIDToCtx(ctx.ID, ctx.Sub, ctx.Type) error
}

type UMADB interface {
	SetPermissionTicket(ctx.Sub, *uma.PermissionTicket) error
	LoadPermissionTicket(ctx.Sub) (*uma.PermissionTicket, error)
	SetRPT(ctx.Sub, *uma.RPT) error
	LoadRPT(ctx.Sub) (*uma.RPT, error)
}

type rx struct {
	c     caep.Rx
	u     *umaClient
	cdb   CtxDB
	trans Translater
}

var _ Rx = &rx{}

func (rx *rx) AddSub(sub ctx.Sub, reqs []ReqCtx) error {
	// caep.EventStream を設定しておく
	if err := rx.setupStream(reqs); err != nil {
		return err
	}
	// subject の stream での status を得る
	if err := rx.isEnabledStatusFor(sub); err != nil {
		// sub が stream で enable でない、 addsub を行う
		if err := rx.addSub(sub, reqs); err != nil {
			// err は pip.Error(ReqSubmitted) を満たす場合あり
			return err
		}
	}
	return nil
}

func (rx *rx) RegisterCtxID(sub ctx.Sub, ct ctx.Type, cid ctx.ID) error {
	return rx.trans.BindCtxIDToCtx(cid, sub, ct)
}

func (rx *rx) RecvCtx(r *http.Request) error {
	event, err := rx.c.Recv(r)
	if err != nil {
		return err
	}
	return rx.cdb.SaveCtxFrom(event)
}

// stream の config が req を満たしているかチェック
// 満たしているとは req に含まれる ctx.Type (=caep.EventType)  が全て config.EventRequested に含まれているか
func (rx *rx) setupStream(reqs []ReqCtx) error {
	var reqEventType []string
	for _, c := range reqs {
		reqEventType = append(reqEventType, string(c.Type.CAEPEventType()))
	}
	newConf := &caep.StreamConfig{
		EventsRequested: reqEventType,
	}
	if err := rx.c.SetUpStream(newConf); err != nil {
		// 更新に失敗したら、終わり
		return err
	}
	return nil
}

func (rx *rx) isEnabledStatusFor(sub ctx.Sub) error {
	// ctx.Sub -> caep.EventSubject 変換
	esub, err := rx.trans.EventSubject(sub)
	if err != nil {
		return fmt.Errorf("sub(%v) は eventSubject に変換できない %v", err)
	}
	// subject の stream での status を得る
	status, err := rx.c.ReadStreamStatus(esub)
	// status が得られなかった、もしくは status.Status が有効でないとき
	if err != nil {
		return err
	}
	if status.Status != "enabled" {
		return fmt.Errorf("status for sub(%v) is not enabled but %v", sub, status)
	}
	return nil
}

func (rx *rx) addSub(sub ctx.Sub, reqs []ReqCtx) error {
	// ctx.Sub -> caep.EventSubject 変換
	esub, err := rx.trans.EventSubject(sub)
	if err != nil {
		return fmt.Errorf("sub(%v) は eventSubject に変換できない %v", err)
	}

	reqscopes := make(map[caep.EventType]struct {
		EventID string            `json:"event_id"`
		Scopes  []caep.EventScope `json:"scopes"`
	})
	for _, rc := range reqs {
		et := rc.Type.CAEPEventType()

		ctxID, err := rx.trans.CtxID(sub, rc.Type)
		if err != nil {
			return fmt.Errorf("sub(%v) の ctxtype(%v) に対応する ctxID がない %v", sub, rc.Type, err)
		}

		var escopes []caep.EventScope
		for _, cs := range rc.Scopes {
			escopes = append(escopes, cs.CAEPEventScope())
		}

		reqscopes[et] = struct {
			EventID string            `json:"event_id"`
			Scopes  []caep.EventScope `json:"scopes"`
		}{ctxID.String(), escopes}
	}
	reqadd := &caep.ReqAddSub{
		Subject:        esub,
		ReqEventScopes: reqscopes,
	}
	err = rx.c.AddSubject(reqadd)
	if err == nil {
		fmt.Printf("caeprecv.AddSub(%#v,%#v) succeeded\n", sub, reqs)
		return nil
	}
	fmt.Printf("caeprecv.AddSub failed %#v\n", err)
	e, ok := err.(caep.RecvError)
	if !ok {
		return err
	}
	if e.Code() == caep.RecvErrorCodeUnAuthorized {
		resp := e.Option().(*http.Response)
		if err := rx.u.ExtractPermissionTicket(sub, resp); err != nil {
			return err
		}
		if err := rx.u.ReqRPT(sub); err != nil {
			fmt.Printf("rx.u.ReqRPT(%#v) failed %#v\n", sub, err)
			return err
		}
		return rx.c.AddSubject(reqadd)
	}
	if e.Code() == caep.RecvErrorCodeNotFound {
		// todo どうしようもないえらー
		return e
	}
	return e
}
