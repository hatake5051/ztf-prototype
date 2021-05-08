package pip

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/hatake5051/ztf-prototype/ac"
	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/ctx"
	"github.com/hatake5051/ztf-prototype/ctx/rx"
	"github.com/hatake5051/ztf-prototype/uma"
)

type CtxPIPConf map[string]struct {
	Rx rx.Conf `json:"rx"`
}

func (conf *CtxPIPConf) new(store SessionStoreForCPIP, ctxDB CtxDB, umaDB rx.UMADB, translater rx.Translater) *cPIP {
	pip := &cPIP{
		repo:    &repo{make(map[string]string), make(map[string][]string)},
		session: store,
	}
	for capURL, capconf := range *conf {
		rx := capconf.Rx.New(ctxDB, umaDB, translater)
		agent := &cPIPForOneCAP{
			capURL:  capURL,
			session: store,
			db:      ctxDB,
			rx:      rx,
		}
		pip.agents.Store(capURL, agent)
		pip.repo.Update(capURL, capconf.Rx.Contexts)
	}
	return pip
}

type CtxDB interface {
	Load(sub ctx.Sub, cts []ctx.Type) ([]ctx.Ctx, error)
	LoadAllFromCAP(capURL string, sub ctx.Sub) []ctx.Ctx
	SaveCtxFrom(*caep.Event) error
}

type cPIP struct {
	repo    *repo
	session SessionStoreForCPIP
	agents  sync.Map
}

type SessionStoreForCPIP interface {
	Identify(session string, cap string) ctx.Sub
}

func (pip *cPIP) Contexts(session string, reqctxs []ac.ReqContext) ([]ctx.Ctx, error) {

	// reqctxs を CAP をキーにしてまとめる
	categorizedReqCtxs := make(map[string][]ac.ReqContext)
	for _, rc := range reqctxs {
		categorizedReqCtxs[pip.repo.CAP(rc.Type())] = append(categorizedReqCtxs[pip.repo.CAP(rc.Type())], rc)
	}
	var ans []ctx.Ctx
	for cap, reqctxs := range categorizedReqCtxs {
		// 絶対 ok っしょ
		v, _ := pip.agents.Load(cap)
		agent := v.(*cPIPForOneCAP)
		sub := pip.session.Identify(session, cap)
		for _, c := range agent.ManagedCtxList(session) {
			if c.ID().String() == "" {
				return nil, newEO(fmt.Errorf("Ctx(%v) の CtxID が設定されていない", c), CtxIDNotRegistered, cap)
			}
		}
		cs, err := agent.Contexts(sub, reqctxs)
		if err != nil {
			return nil, err
		}
		ans = append(ans, cs...)

	}
	return ans, nil
}

func (pip *cPIP) ContextAgent(cap string) (interface{}, error) {
	// 絶対 ok っしょ
	v, _ := pip.agents.Load(cap)
	agent := v.(*cPIPForOneCAP)
	return agent, nil
}

type repo struct {
	db1 map[string]string
	db2 map[string][]string
}

func (r *repo) Update(capURL string, contexts map[string][]string) {
	for ctxType, _ := range contexts {
		r.db1[ctxType] = capURL
		r.db2[capURL] = append(r.db2[capURL], ctxType)
	}
}

func (r *repo) CAP(ct ctx.Type) string {
	return r.db1[ct.String()]
}

func (r *repo) CtxTypes(CAPURL string) []ctx.Type {
	var ret []ctx.Type
	for _, sct := range r.db2[CAPURL] {
		ret = append(ret, ctx.NewCtxType(sct))
	}
	return ret
}

// cPIPForOneCAP はある CAP が管理するコンテキストを扱う PIP
type cPIPForOneCAP struct {
	capURL  string
	session SessionStoreForCPIP
	db      CtxDB
	rx      rx.Rx
}

var _ RxCtxAgent = &cPIPForOneCAP{}

func (pip *cPIPForOneCAP) Contexts(sub ctx.Sub, reqctxs []ac.ReqContext) ([]ctx.Ctx, error) {
	var reqs []rx.ReqCtx
	var css []ctx.Type
	for _, rc := range reqctxs {
		reqs = append(reqs, rx.ReqCtx{Type: rc.Type(), Scopes: rc.Scopes()})
		css = append(css, rc.Type())
	}
	if err := pip.rx.AddSub(sub, reqs); err != nil {
		if err, ok := err.(*uma.ReqRPTError); ok {
			return nil, newE(err, SubjectForCtxUnAuthorizeButReqSubmitted)
		}
	}
	return pip.db.Load(sub, css)
}

func (pip *cPIPForOneCAP) SetCtxID(session, ctxType, ctxID string) error {
	sub := pip.session.Identify(session, pip.capURL)
	return pip.rx.RegisterCtxID(sub, ctx.NewCtxType(ctxType), ctx.NewCtxID(ctxID))
}

func (pip *cPIPForOneCAP) RecvCtx(r *http.Request) error {
	return pip.rx.RecvCtx(r)
}

func (pip *cPIPForOneCAP) ManagedCtxList(session string) []ctx.Ctx {
	sub := pip.session.Identify(session, pip.capURL)
	return pip.db.LoadAllFromCAP(pip.capURL, sub)
}
