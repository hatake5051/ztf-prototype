package pip

import (
	"fmt"

	"github.com/hatake5051/ztf-prototype/ac"
	acpip "github.com/hatake5051/ztf-prototype/ac/pip"
	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/uma"
)

type ctxType string
type ctxScope string

// ctx は ac.Context implementation
type ctx struct {
	Sub         *subForCtx
	Type        ctxType
	ScopeValues map[ctxScope]string
	ResID       uma.ResID
}

// ToAC は pip.ctx を ac.Context interface に適応させる
func (c *ctx) ToAC() ac.Context {
	return &wrapC{c}
}

// reqCtx は PDP が要求するコンテキストの名前とそのスコープを表す
type reqCtx struct {
	Type   ctxType
	Scopes []ctxScope
}

func fromACReqCtx(req ac.ReqContext) reqCtx {
	var scopes []ctxScope
	for _, s := range req.Scopes() {
		scopes = append(scopes, ctxScope(s))
	}
	return reqCtx{
		Type:   ctxType(req.Type()),
		Scopes: scopes,
	}
}

// subForCtx はある ctx の subject を表す
type subForCtx struct {
	PID      string
	DeviceID string
}

func (s *subForCtx) Identifier() string {
	if s.DeviceID != "" {
		return fmt.Sprintf("sub:%s:dev:%s", s.PID, s.DeviceID)
	}
	return fmt.Sprintf("sub:%s", s.PID)
}

func NewSubForCtxFromCAEPSub(se *caep.EventSubject) *subForCtx {
	return &subForCtx{
		PID:      se.User["opaque"],
		DeviceID: se.Device["opaque"],
	}

}

func (sub *subForCtx) toCAEP() *caep.EventSubject {
	ans := &caep.EventSubject{
		User: map[string]string{
			"foramt": "opaque",
			"opaque": sub.PID,
		},
	}
	if sub.DeviceID != "" {
		ans.Device = map[string]string{
			"format": "opaque",
			"opaque": sub.DeviceID,
		}
	}
	return ans
}

// CtxPIPConf は ctxPIP の設定情報
type CtxPIPConf struct {
	// CtxID2CAP はコンテキストType -> そのコンテキストを管理するCAP名
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

	caps := make(map[ctxType]string)
	for k, v := range conf.CtxID2CAP {
		caps[ctxType(k)] = v
	}

	return &ctxPIP{caps, ctxManagers}, nil
}

// ctxPIP は PIP のなかで context を管理する
type ctxPIP struct {
	caps     map[ctxType]string //map[ctx.name]cap
	managers map[string]ctxManager
}

func (pip *ctxPIP) GetAll(session string, req []reqCtx) ([]ctx, error) {
	reqs := pip.categorize(req)
	var ret []ctx
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

func (pip *ctxPIP) Agent(collector string) (acpip.RxCtxAgent, error) {
	cm := pip.manager(collector)
	return cm.Agent()
}

// categorize は reqCtx を CAP ごとに分類する
func (pip *ctxPIP) categorize(req []reqCtx) map[string][]reqCtx {
	ret := make(map[string][]reqCtx)
	for _, r := range req {
		cap := pip.caps[r.Type]
		ret[cap] = append(ret[cap], r)
	}
	return ret
}

// manager はCAPに対応するそのRPやCTXDBをまとめた ctxManager を返す
func (pip *ctxPIP) manager(cap string) ctxManager {
	return pip.managers[cap]
}

// ctxManager はコンテキストを管理する
// コンテキストはある collector が集めているものをまとめて管理している
type ctxManager interface {
	Get(session string, req []reqCtx) ([]ctx, error)
	Agent() (acpip.RxCtxAgent, error)
}

// smForCtxmanager は session と subject の紐付けを管理する
type smForCtxManager interface {
	Load(session string) (*subForCtx, error)
	Set(session string, sub *subForCtx) error
}

// ctxDB はコンテキストを保存する
type ctxDB interface {
	Load(sub *subForCtx, req []reqCtx) ([]ctx, error)
	Set(sub *subForCtx, c *ctx) error
	UMAResID(*subForCtx, ctxType) (uma.ResID, error)
}

// wrapC は ctx を ac.Context impl させるラッパー
type wrapC struct {
	c *ctx
}

func (w wrapC) Type() string {
	return string(w.c.Type)
}

func (w wrapC) ScopeValues() map[string]string {
	ans := make(map[string]string)
	for k, v := range w.c.ScopeValues {
		ans[string(k)] = v
	}
	return ans
}
