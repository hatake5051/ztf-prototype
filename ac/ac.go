package ac

import (
	"fmt"
	"net/http"
	"sync"
)

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

// Context はアクセス要求に関するアクセス判断に用いられる情報を表す
type Context interface {
	ID() string
	// Scopes() []string
	ScopeValues() map[string]string
}

// ReqContext はアクセス要求の判断に必要なコンテキスト要求を表す
type ReqContext interface {
	ID() string
	Scopes() []string
}

// Controller は PEP の実装で必要なアクセス管理機構を提供する
type Controller interface {
	AskForAuthorization(session string, res Resource, a Action) error
	SubAgent(idp string) (AuthNAgent, error)
	CtxAgent(cap string) (CtxAgent, error)
}

// AuthNAgent は OIDC フローを実装する
type AuthNAgent interface {
	Redirect(w http.ResponseWriter, r *http.Request)
	Callback(session string, r *http.Request) error
}

// CtxAgent は ctx のための sub 認証のため OIDC Flow を行う
// さらに外部で収集したコンテキストを収集する
type CtxAgent interface {
	AuthNAgent
	RecvCtx(r *http.Request) error
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
	// RequestDenied は認可判断の結果認可が下りなかったことを表す
	RequestDenied
	// IndeterminateForCtxNotFound はコンテキストが十分に集まっていないため、判断できないことを示す(間隔を置いてアクセスしてくれって感じ)
	IndeterminateForCtxNotFound
)

// PDP は認可判断の主体
type PDP interface {
	NotifiedOfRequest(Subject, Resource, Action) (reqctxs []ReqContext, deny bool)
	Decision(Subject, Resource, Action, []Context) error
}

// PIP はサブジェクトやコンテキストを管理する
type PIP interface {
	GetSubject(session string) (Subject, error)
	SubjectAuthNAgent(idp string) (AuthNAgent, error)
	GetContexts(session string, reqctxs []ReqContext) ([]Context, error)
	ContextAgent(cap string) (CtxAgent, error)
}

// Repository はいろんなものを保存する場所
type Repository interface {
	KeyPrefix() string
	Save(key string, b []byte) error
	Load(key string) (b []byte, err error)
}

func NewRepo() Repository {
	return &repo{r: make(map[string][]byte)}
}

type repo struct {
	m sync.RWMutex
	r map[string][]byte
}

func (r *repo) KeyPrefix() string {
	return "repo"
}

func (r *repo) Save(key string, b []byte) error {
	r.m.Lock()
	defer r.m.Unlock()
	r.r[key] = b
	return nil
}

func (r *repo) Load(key string) (b []byte, err error) {
	r.m.RLock()
	defer r.m.RUnlock()
	b, ok := r.r[key]
	if !ok {
		return nil, fmt.Errorf("key(%s) にはまだ保存されていない", key)
	}
	return b, nil
}
