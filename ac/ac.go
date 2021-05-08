package ac

import "github.com/hatake5051/ztf-prototype/ctx"

// Subject はアクセス要求者を表す
type Subject interface {
	ID() string
}

// Resource はアクセス要求先を表す
type Resource interface {
	ID() string
}

// Action はアクセス要求先に対して行う動作を表す
type Action interface {
	ID() string
}

// ReqContext はアクセス要求の判断に必要なコンテキスト要求を表す
type ReqContext interface {
	Type() ctx.Type
	Scopes() []ctx.Scope
}

// Error は Controller の処理中に発生したエラーを表す
type Error interface {
	error
	ID() ErrorCode
	Option() string
}

// ErrorCode は Controller の処理中に発生したエラーの種類を表す
type ErrorCode int

const (
	// SubjectNotAuthenticated はさぶじぇくとが未認証であることを表す
	// Option は空文字でない場合どのエージェントを使うか指定してある
	SubjectNotAuthenticated ErrorCode = iota + 1
	// SubjectForCtxUnAuthorizedButReqSubmitted は認可判断をできるポリシーを持っていないため、Controller がポリシー設定者に設定を要求したことを示す
	// Option はなし
	SubjectForCtxUnAuthorizedButReqSubmitted
	// CtxIDNotRegistered は Context の CtxID が設定されていないことを表す。
	// Option() として登録すべき cap-host string を返す。
	CtxIDNotRegistered
	// RequestDenied は認可判断の結果認可が下りなかったことを表す
	RequestDenied
	// IndeterminateForCtxNotFound はコンテキストが十分に集まっていないため、判断できないことを示す(間隔を置いてアクセスしてくれって感じ)
	IndeterminateForCtxNotFound
)
