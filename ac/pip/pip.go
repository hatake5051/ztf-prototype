package pip

import (
	"net/http"

	"github.com/hatake5051/ztf-prototype/ac"
)

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
	// Option() として cap-host string を返す
	SubjectForCtxUnAuthenticated
	// SubjectForCtxUnAuthorizeButReqSubmitted はUMA Authz process で res owner の許可待ち状態であることを表す
	SubjectForCtxUnAuthorizeButReqSubmitted
	// CtxsNotFound は ctx をまだ rp が所持していないことを表す(CAPからもらう認可は下りているが、まだCAP からもらっていないとか)
	CtxsNotFound
)

// AuthNAgent は OIDC フローを実装する
type AuthNAgent interface {
	Redirect(w http.ResponseWriter, r *http.Request)
	// Callback は r から idtoken を抽出し session と紐づけて保存する
	Callback(session string, r *http.Request) error
}

// CtxAgent は ctx のための sub 認証のため OIDC Flow を行う
// さらに外部で収集したコンテキストを収集する
type CtxAgent interface {
	AuthNAgent
	RecvCtx(r *http.Request) error
}

// PIP はサブジェクトやコンテキストを管理する
type PIP interface {
	GetSubject(session string) (ac.Subject, error)
	SubjectAuthNAgent(idp string) (AuthNAgent, error)
	GetContexts(session string, reqctxs []ac.ReqContext) ([]ac.Context, error)
	ContextAgent(cap string) (CtxAgent, error)
}
