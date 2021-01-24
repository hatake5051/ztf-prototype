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
	// GetSubject は session に紐づくユーザ情報を返す
	// session に紐づくユーザ情報がない場合 (e.g. 認証がまだ)などのときは
	// SubjectUnAuthenticated エラーを返す
	GetSubject(session string) (ac.Subject, error)
	// SubjectAuthNAgent は idp に対応する認証エージェントを返す
	// このエージェントは OpenID Connect の RP として振る舞うことができるため
	// このエージェントのためのエンドポイントを ZTF の RP は準備する
	SubjectAuthNAgent(idp string) (AuthNAgent, error)
	// GetContexts は session に紐づくユーザのコンテキストを返す
	// reqctxs はどのコンテキストをどれほどの粒度で求めているか PIP に伝えることができる
	// session に紐づくユーザ情報がない場合 (e.g. 認証がまだ)などのときは
	// SubjectForCtxUnAuthenticated エラーコードを返す
	// コンテキストを CAP からもらうにはユーザの承認が必要なときは
	// SubjectForCtxUnAuthorizeButReqSubmitted
	// コンテキストを CAP からまだ提供されていないときは
	// CtxsNotFound
	GetContexts(session string, reqctxs []ac.ReqContext) ([]ac.Context, error)
	ContextAgent(cap string) (CtxAgent, error)
}
