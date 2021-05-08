package pip

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/hatake5051/ztf-prototype/ac"
	"github.com/hatake5051/ztf-prototype/ctx"
	"github.com/hatake5051/ztf-prototype/ctx/rx"
	"github.com/hatake5051/ztf-prototype/ctx/tx"
)

type Conf struct {
	Sub SubPIPConf `json:"sub"`
	Ctx CtxPIPConf `json:"ctx"`
}

func (conf *Conf) New(sstore SessionStoreForSPIP, cstore SessionStoreForCPIP, ctxDB CtxDB, umaDB rx.UMADB, translaterForRx rx.Translater, rxDB tx.RxDB, translaterForTx tx.Translater) PIP {
	spip := conf.Sub.new(sstore)
	cpip := conf.Ctx.new(cstore, ctxDB, umaDB, translaterForRx, rxDB, translaterForTx)
	return &struct {
		*sPIP
		*cPIP
	}{spip, cpip}
}

// PIP はサブジェクトやコンテキストを管理する
type PIP interface {
	// Subject は session に紐づくユーザ情報を返す。
	// session に紐づくユーザ情報がない場合 (e.g. 認証がまだ)などのときは、
	// SubjectUnAuthenticated エラーを返す
	Subject(session string) (ac.Subject, error)
	// SubjectAuthNAgent は idp に対応する認証エージェントを返す。
	// このエージェントは OpenID Connect の RP として振る舞うことができるため、
	// このエージェントのためのエンドポイントを PEP は展開する
	SubjectAuthNAgent(idp string) (AuthNAgent, error)
	// Contexts は session に紐づくユーザのコンテキストを返す。
	// reqctxs はどのコンテキストをどれほどの粒度で求めているか PIP に伝えることができる。
	// session に紐づくユーザ情報がない場合 (e.g. 認証がまだ)などのときは
	// SubjectForCtxUnAuthenticated を、
	// コンテキストを CAP からもらうにはユーザの承認が必要なときは
	// SubjectForCtxUnAuthorizeButReqSubmitted を、
	// コンテキストを CAP からまだ提供されていないときは
	// CtxsNotFound をエラーコードとして返す
	Contexts(session string, reqctxs []ac.ReqContext) ([]ctx.Ctx, error)
	// ContextAgent は cap に対するエージェントを返す。
	// CAP が一方的にコンテキストを提供する場合であれば RxCtxAgent を、
	// CAP が双方向のコンテキスト連携を求める場合であれば TxRxCtxAgent を返す
	ContextAgent(cap string) (interface{}, error)
}

// AuthNAgent はユーザを認証するエージェントを返す。
// このエージェントは OpenID Connect RP としてユーザの認証結果を受け取る。
// 受け取った ID Token は PIP に保存され、セッションと紐付けられて管理される
type AuthNAgent interface {
	Redirect(w http.ResponseWriter, r *http.Request)
	// Callback は r から idtoken を抽出し session と紐づけて保存する
	Callback(session string, r *http.Request) error
}

// RxCtxAgent は CAP からコンテキストを収集するエージェントを返す。
type RxCtxAgent interface {
	RecvCtx(r *http.Request) error
	SetCtxID(session, ctxType, ctxID string) error
	ManagedCtxList(session string) []ctx.Ctx
}

// TxRxCtxAgent は CAP からコンテキストを収集するだけでなく、
// コンテキストを CAP へ提供するエージェントを返す。
type TxRxCtxAgent interface {
	RxCtxAgent
	WellKnown() (path string, h http.HandlerFunc)
	Router(r *mux.Router) (protectedPath []string)
	Collect(r *http.Request)
}

// ErrorCode は PIP で発生したエラー情報を伝える
type ErrorCode int

const (
	// SubjectUnAuthenticated はSubject が認証されていないことを表す。
	SubjectUnAuthenticated ErrorCode = iota + 1
	// SubjectForCtxUnAuthenticated はContext の Subject が認証されていないことを表す。
	// Option() として cap-host string を返す。
	SubjectForCtxUnAuthenticated
	// CtxIDNotRegistered は Context の CtxID が設定されていないことを表す。
	// Option() として登録すべき cap-host string を返す。
	CtxIDNotRegistered
	// SubjectForCtxUnAuthorizeButReqSubmitted はUMA Authz process で res owner の許可待ち状態であることを表す
	SubjectForCtxUnAuthorizeButReqSubmitted
	// CtxsNotFound は ctx をまだ rp が所持していないことを表す(CAPからもらう認可は下りているが、まだCAP からもらっていないとか)
	CtxsNotFound
)

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

// Error は PIP で発生した外部で処理すべきエラー
type Error interface {
	error
	Code() ErrorCode
	Option() interface{}
}
