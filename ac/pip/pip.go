package pip

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
