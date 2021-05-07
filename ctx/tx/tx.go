package tx

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/ctx"
	"github.com/hatake5051/ztf-prototype/uma"
)

func (conf *Conf) New(rxDB RxDB, ctxDB CtxDB, trans Translater, store SessionStore) Tx {
	umaressrv := conf.UMA.to().New(&ressrvDB{})
	u := &umaResSrv{
		umaressrv, store, ctxDB, trans,
	}

	var eventsupported []string
	for ct := range conf.Contexts {
		eventsupported = append(eventsupported, ct)
	}
	c := conf.CAEP.new(eventsupported, conf.UMA.JwksURI, rxDB, umaressrv, trans)
	return &tx{
		rxDB, trans, c, u,
	}
}

type Tx interface {
	WellKnown() (path string, h http.HandlerFunc)
	Router(r *mux.Router) (protectedPath []string)
	Transmit(c ctx.Ctx) error
}

type RxDB interface {
	Load(rxID caep.RxID) (*caep.Receiver, error)
	Save(recv *caep.Receiver) error
	Auds(ct ctx.Type) ([]caep.Receiver, error)

	LoadStatus(rxID caep.RxID, sub *caep.EventSubject) (*caep.StreamStatus, error)
	SaveStatus(rxID caep.RxID, status *caep.StreamStatus) error
}

type CtxDB interface {
	// LoadCtx は Sub と ctx を指定してそのコンテキストを受け取る
	LoadCtx(ctx.Sub, ctx.Type) (ctx.Ctx, error)
	LoadAll(ctx.Sub) ([]ctx.Ctx, error)
}

type Translater interface {
	EventSubject(ctx.Sub, caep.RxID) (*caep.EventSubject, error)
	ResID(ctx.ID) (uma.ResID, error)
	BindEventSubjectToResID(caep.RxID, *caep.EventSubject, uma.ResID) error
	BindResIDToSub(uma.ResID, ctx.Sub, ctx.Type) error
}

type tx struct {
	rxDB  RxDB
	trans Translater
	c     caep.Tx
	u     *umaResSrv
}

var _ Tx = &tx{}

func (tx *tx) WellKnown() (string, http.HandlerFunc) {
	return "/sse-configuration", tx.c.WellKnown
}

func (tx *tx) Router(r *mux.Router) []string {
	tx.c.Router(r)
	u := r.PathPrefix("/uma").Subrouter()
	u.HandleFunc("/list", tx.u.list)
	u.HandleFunc("/ctx", tx.u.crud)
	u.HandleFunc("/pat/callback", tx.u.callBack)

	return []string{"/uma/list", "/uma/ctx", "/uma/pat/callback"}
}

func (tx *tx) Transmit(c ctx.Ctx) error {
	recvs, err := tx.rxDB.Auds(c.Type())
	if err != nil {
		return fmt.Errorf("tx.rxDB.Auds in tx.Transmit で失敗 %v", err)
	}
	for _, recv := range recvs {
		aud := []caep.Receiver{recv}

		sub, err := tx.trans.EventSubject(c.Sub(), recv.ID)
		if err != nil {
			return fmt.Errorf("Receiver(%v) は sub(%v) を登録していない %v", recv, c.Sub(), err)
		}
		status, err := tx.rxDB.LoadStatus(recv.ID, sub)
		if err != nil {
			return fmt.Errorf("Receiver(%v) には sub(%v) が登録されてないみたい %v", recv, sub, err)
		}
		if status.Status != "enabled" {
			return fmt.Errorf("Receiver(%v) の sub(%v) の status(%v) が enabled でない", recv, sub, status)
		}
		authorizedScopes := status.EventScopes[c.Type().CAEPEventType()]
		prop := make(map[caep.EventScope]string)
		for _, scope := range authorizedScopes {
			prop[scope] = c.Value(ctx.NewCtxScopeFromCAEPEventScope(scope))
		}

		ev := &caep.Event{
			Type:     c.Type().CAEPEventType(),
			Subject:  sub,
			Property: prop,
		}
		if err := tx.c.Transmit(aud, ev); err != nil {
			return fmt.Errorf("送信に失敗 to Rx(%v) %v because %v\n", recv, ev, err)
		}
	}
	return nil
}
