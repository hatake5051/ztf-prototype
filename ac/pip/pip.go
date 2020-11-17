package pip

import "github.com/hatake5051/ztf-prototype/ac"

// Error は PIP で発生した外部で処理すべきエラー
type Error interface {
	error
	Code() ErrorCode
	Option() interface{}
}

// ErrorCode は PIP で発生したエラー情報を伝える
type ErrorCode int

const (
	// SubjectUnAuthenticated はSubject が認証されていないことを表す
	SubjectUnAuthenticated ErrorCode = iota + 1
	// SubjectForCtxUnAuthenticated はContext の Subject が認証されていないことを表す
	// Option() として collector string を返す
	SubjectForCtxUnAuthenticated
	// SubjectForCtxUnAuthorizedButReqSubmitted はUMA Authz process で res owner の許可待ち状態であることを表す
	SubjectForCtxUnAuthorizeButReqSubmitted
	// CtxsNotFound は ctx をまだ rp が所持していないことを表す(CAPからもらう認可は下りているが、まだCAP からもらっていないとか)
	CtxsNotFound
)

// Conf は PIP を構成するのに必要な設定情報
type Conf struct {
	*SubPIPConf
	*CtxPIPConf
}

// New は設定情報をもとに PIP を構成する
func (conf *Conf) New(repo ac.Repository) (ac.PIP, error) {
	s := conf.SubPIPConf.new(
		&smForSubPIPimpl{repo, "subpip-sm"},
		&subDBimple{repo, "subpip-db"},
	)
	sm := make(map[string]smForCtxManager)
	db := make(map[string]ctxDB)
	umaClientDB := make(map[string]umaClientDB)
	for collector := range conf.CtxPIPConf.CAP2RP {
		sm[collector] = &smForCtxManagerimple{repo, "ctxpip-sm:" + collector}
		db[collector] = &ctxDBimple{repo, "ctxpip-db:" + collector}
		umaClientDB[collector] = &umaClientDBimpl{repo, "ctxpip-umadb:" + collector}
	}
	c, err := conf.CtxPIPConf.new(sm, db, umaClientDB)
	if err != nil {
		return nil, err
	}
	return &pip{s, c}, nil
}

type pip struct {
	sub *subPIP
	ctx *ctxPIP
}

func (pip *pip) GetSubject(session string) (ac.Subject, error) {
	sub, err := pip.sub.Get(session)
	if err != nil {
		return nil, err
	}
	return sub.ToACSub(), nil
}
func (pip *pip) SubjectAuthNAgent(issuer string) (ac.AuthNAgent, error) {
	a, err := pip.sub.Agent(issuer)
	if err != nil {
		return nil, err
	}
	return a, nil
}
func (pip *pip) GetContexts(session string, reqctxs []ac.ReqContext) ([]ac.Context, error) {
	var reqs []reqCtx
	for _, c := range reqctxs {
		reqs = append(reqs, fromACReqCtx(c))
	}
	ctxs, err := pip.ctx.GetAll(session, reqs)
	if err != nil {
		return nil, err
	}
	var ret []ac.Context
	for _, c := range ctxs {
		ret = append(ret, &wrapC{&c})
	}
	return ret, nil

}
func (pip *pip) ContextAgent(collector string) (ac.CtxAgent, error) {
	a, err := pip.ctx.Agent(collector)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// e implements pip.Error
type e struct {
	error
	code ErrorCode
	opt  interface{}
}

func (e *e) Code() ErrorCode {
	return e.code
}

func (e *e) Option() interface{} {
	return e.opt
}

func newE(err error, code ErrorCode) *e {
	return &e{err, code, nil}
}
func newEO(err error, code ErrorCode, opt interface{}) *e {
	return &e{err, code, opt}
}
