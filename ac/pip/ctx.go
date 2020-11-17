package pip

import (
	"net/http"

	"github.com/hatake5051/ztf-prototype/ac"
	"github.com/hatake5051/ztf-prototype/caep"
)

// ctx は ac.Context implementation
type ctx struct {
	ID          string
	ScopeValues map[string]string
}

// ToAC は pip.ctx を ac.Context interface に適応させる
func (c *ctx) ToAC() ac.Context {
	return &wrapC{c}
}

func fromCAEPCtx(c *caep.Context) *ctx {
	return &ctx{
		ID:          c.ID,
		ScopeValues: c.ScopeValues,
	}
}

// reqCtx は PDP が要求するコンテキストの名前とそのスコープを表す
type reqCtx struct {
	ID     string
	Scopes []string
}

func fromACReqCtx(req ac.ReqContext) reqCtx {
	return reqCtx{
		ID:     req.ID(),
		Scopes: req.Scopes(),
	}
}

// subForCtx はある ctx の subject を表す
type subForCtx struct {
	SpagID string
}

// CtxPIPConf は ctxPIP の設定情報
type CtxPIPConf struct {
	// CtxID2CAP はコンテキストID -> そのコンテキストを管理するCAP名
	CtxID2CAP map[string]string
	// Cap2RPConf は CAP 名 -> その CAP に対する RP 設定情報
	CAP2RP map[string]*CAPRPConf
}

func (conf *CtxPIPConf) new(sm map[string]smForCtxManager, db map[string]ctxDB, umaClientDB map[string]umaClientDB) (*ctxPIP, error) {
	ctxManagers := make(map[string]ctxManager)
	for collector, conf := range conf.CAP2RP {
		cm, err := conf.new(sm[collector], db[collector], umaClientDB[collector])
		if err != nil {
			return nil, err
		}
		ctxManagers[collector] = cm
	}

	return &ctxPIP{conf.CtxID2CAP, ctxManagers}, nil
}

// ctxPIP は PIP のなかで context を管理する
type ctxPIP struct {
	caps     map[string]string //map[ctx.name]cap
	managers map[string]ctxManager
}

func (pip *ctxPIP) GetAll(session string, req []reqCtx) ([]ctx, error) {
	reqs := pip.categorize(req)
	var ret []ctx
	// TODO: concurrency
	for cap, reqctxs := range reqs {
		ctxManager := pip.manager(cap)
		ctx, err := ctxManager.Get(session, reqctxs)
		if err != nil {
			return nil, err
		}
		ret = append(ret, ctx...)
	}
	return ret, nil
}

func (pip *ctxPIP) Agent(collector string) (ac.CtxAgent, error) {
	cm := pip.manager(collector)
	return cm.Agent()
}

// categorize は reqCtx を CAP ごとに分類する
func (pip *ctxPIP) categorize(req []reqCtx) map[string][]reqCtx {
	ret := make(map[string][]reqCtx)
	for _, r := range req {
		cap := pip.caps[r.ID]
		ret[cap] = append(ret[cap], r)
	}
	return ret
}

// manager はCAPに対応するそのRPやCTXDBをまとめた ctxManager を返す
func (pip *ctxPIP) manager(cap string) ctxManager {
	return pip.managers[cap]
}

type ctxagent struct {
	*authnagent
	setCtx func(*http.Request) error
}

func (a *ctxagent) RecvCtx(r *http.Request) error {
	return a.setCtx(r)
}

// ctxManager はコンテキストを管理する
// コンテキストはある collector が集めているものをまとめて管理している
type ctxManager interface {
	Get(session string, req []reqCtx) ([]ctx, error)
	Agent() (ac.CtxAgent, error)
}

// smForCtxmanager は session と subject の紐付けを管理する
type smForCtxManager interface {
	Load(session string) (*subForCtx, error)
	Set(session string, sub *subForCtx) error
}

// ctxDB はコンテキストを保存する
type ctxDB interface {
	Load(sub *subForCtx, req []reqCtx) ([]ctx, error)
	Set(spagID string, c *ctx) error
}

// wrapC は ctx を ac.Context impl させるラッパー
type wrapC struct {
	c *ctx
}

func (w wrapC) ID() string {
	return w.c.ID
}

func (w wrapC) ScopeValues() map[string]string {
	return w.c.ScopeValues
}
