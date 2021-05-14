package tx

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/ctx"
	"github.com/hatake5051/ztf-prototype/uma"
)

// New は tx.Conf の内容から tx.Tx を構築する。
// Tx は uma.ResSrv と caep.Transmitter からなり、
// それぞれを構築するための必要な引数を渡す。
func (conf *Conf) New(uma struct {
	Store SessionStoreForUMA
	Ctxs  CtxDBForUMA
	Trans TranslaterForUMA
}, caep struct {
	Notification func(ctx.Sub, []ctx.Type) error
	Trans        TranslaterForCAEP
}) Tx {
	u := conf.UMA.new(uma.Store, uma.Ctxs, uma.Trans)

	var eventsupported []string
	for ct := range conf.Contexts {
		eventsupported = append(eventsupported, ct)
	}
	c := conf.CAEP.new(eventsupported, u, caep.Notification, caep.Trans)
	return &tx{c, u}
}

// TranslaterForCAEP は caep.Transmitter を動かす上で必要な変換を担う。
type TranslaterForCAEP interface {
	CtxID(eventID string) (ctx.ID, error)
	EventType(ctx.Type) caep.EventType
	CtxType(caep.EventType) ctx.Type
	CtxSub(caep.RxID, *caep.EventSubject) (ctx.Sub, error)
	EventSubject(ctx.ID, caep.RxID) (*caep.EventSubject, error)
	CtxScopes(t caep.EventType, scopes []caep.EventScope) ([]ctx.Scope, error)
	BindEventSubjectToCtxID(caep.RxID, *caep.EventSubject, ctx.ID) error
}

// UMAResSrv で使うセッションを管理する sessionStore
type SessionStoreForUMA interface {
	// IdentifySubject は今現在アクセスしてきているサブジェクトの識別子を返す
	IdentifySubject(r *http.Request) (ctx.Sub, error)
	// LoadRedirectBack はセッションに紐づいて保存しておいたリダイレクトURLを返す
	LoadAndDeleteRedirectBack(r *http.Request) (redirectURL string)
	// SetRedirectBack はセッションに次進むべきURLを保存する
	SetRedirectBack(r *http.Request, w http.ResponseWriter, redirectURL string) error
}

type CtxDBForUMA interface {
	LoadAllOfSub(ctx.Sub) ([]ctx.Ctx, error)
	LoadCtxOfSub(ctx.Sub, ctx.Type) (ctx.Ctx, error)
}

type TranslaterForUMA interface {
	Res(ctx.Ctx) (*uma.Res, error)
	BindResToCtx(*uma.Res, ctx.Ctx) error
	ReBindRes(*uma.Res) error
	ResReq(ctx.ID, []ctx.Scope) (uma.ResReqForPT, error)
}

// Tx は ZTF でコンテキストを送信する機能を提供する
type Tx interface {
	// WellKnown は ZTF でコンテキスト送信者の設定情報を /.well-known/path で返すようなハンドラを用意する。
	// 現在は CAEP Transmitter Configuration そのものである。
	WellKnown() (path string, h http.HandlerFunc)
	// Router は Router にコンテキスト提供に必要なエンドポイントをはやしていく。
	// CAEP transmitter のエンドポイントと、 UMA resource server のエンドポイントを生やす。
	Router(r *mux.Router) (statefulPaths []string)
	// Transmit はコンテキストを適切なコンテキスト受信者に送信する。
	Transmit(context context.Context, c ctx.Ctx) error
}

type tx struct {
	c *caepTx
	u *umaResSrv
}

var _ Tx = &tx{}

func (tx *tx) WellKnown() (string, http.HandlerFunc) {
	return "/sse-configuration", tx.c.caep.WellKnown
}

func (tx *tx) Router(r *mux.Router) []string {
	tx.c.caep.Router(r)
	u := r.PathPrefix("/uma").Subrouter()
	u.HandleFunc("/list", tx.u.list)
	u.HandleFunc("/ctx", tx.u.crud)
	u.HandleFunc("/pat/callback", tx.u.callBack)

	return []string{"/uma/list", "/uma/ctx", "/uma/pat/callback"}
}

func (tx *tx) Transmit(context context.Context, c ctx.Ctx) error {
	return tx.c.Transmit(context, c)
}
