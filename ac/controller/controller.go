package controller

import (
	"fmt"

	"github.com/hatake5051/ztf-prototype/ac"
	"github.com/hatake5051/ztf-prototype/ac/pdp"
	"github.com/hatake5051/ztf-prototype/ac/pip"
)

// Controller は PEP の実装で必要なアクセス管理機構を提供する
type Controller interface {
	// AskForAuthorization は PEP が PDP に認可判断を尋ねる
	// ユーザの識別がまだ、認証がまだ、コンテキストの取得がまだの場合などはエラーを返す
	AskForAuthorization(session string, res ac.Resource, a ac.Action) error
	// AuthNAgent は Controller の代わりにユーザを認証するエージェントを返す。
	// idp に IdP の URL を設定することで使用する IdP を選択できる
	// このエージェントは OpenID Connect RP としてユーザの認証結果を受け取る。
	// 受け取った ID Token は PIP に保存され、セッションと紐付けられて管理される
	AuthNAgent(idp string) (pip.AuthNAgent, error)
	// CtxAgent は Controller の代わりにコンテキストを収集するエージェントを返す
	// このエージェントは CAP から CAEP Receiver としてコンテキストを受け取る。
	// 受け取ったコンテキストは PIP に保存され、ユーザと紐付けられて管理される
	// さらに、設定に応じて CAP へ CAEP Transmitter としてコンテキストを提供する。
	// CAEP Receiver としてのみ機能する場合は pip.RxCtxAgent を、
	// CAEP Transmitter としても機能する場合は pip.TxRxCtxAgent を返り値は満たす
	CtxAgent(cap string) (interface{}, error)
}

// New は PIP と PDP を受け取って Controller を構成する
func New(pip pip.PIP, pdp pdp.PDP) Controller {
	return &ctrl{pip, pdp}
}

type ctrl struct {
	pip.PIP
	pdp.PDP
}

func (c *ctrl) AskForAuthorization(session string, res ac.Resource, a ac.Action) error {
	// すでに Subject in Access Request が認証済みでセッションが確立しているか確認
	sub, err := c.PIP.GetSubject(session)
	if err != nil {
		if err, ok := err.(pip.Error); ok {
			if err.Code() == pip.SubjectUnAuthenticated {
				return newE(err, ac.SubjectNotAuthenticated)
			}
			return err
		}
		return err
	}
	// Access Request を認可するのに必要なコンテキストを確認
	reqctxs, deny := c.PDP.NotifiedOfRequest(sub, res, a)
	if deny {
		// Contextに関係なくその Access Requst は認可できない
		return newE(fmt.Errorf("the subject(%v) is not arrowed to the action(%v) on the resource(%v)", sub.ID(), a.ID(), res.ID()), ac.RequestDenied)
	}
	// すでにコンテキストの Subject とセッションが確立しているか確認
	ctxs, err := c.PIP.GetContexts(session, reqctxs)
	if err != nil {
		if err, ok := err.(pip.Error); ok {
			switch err.Code() {
			case pip.SubjectForCtxUnAuthenticated:
				return newEO(err, ac.SubjectNotAuthenticated, err.Option().(string))
			case pip.SubjectForCtxUnAuthorizeButReqSubmitted:
				return newE(err, ac.SubjectForCtxUnAuthorizedButReqSubmitted)
			case pip.CtxsNotFound:
				return newE(err, ac.IndeterminateForCtxNotFound)
			default:
				return err
			}
		}
		return err
	}
	return c.PDP.Decision(sub, res, a, ctxs)
}

func (c *ctrl) AuthNAgent(idp string) (pip.AuthNAgent, error) {
	return c.PIP.SubjectAuthNAgent(idp)
}

func (c *ctrl) CtxAgent(cap string) (interface{}, error) {
	return c.PIP.ContextAgent(cap)
}

type e struct {
	error
	id ac.ErrorCode
	o  string
}

func newE(err error, id ac.ErrorCode) ac.Error {
	return &e{err, id, ""}
}

func newEO(err error, id ac.ErrorCode, option string) ac.Error {
	return &e{err, id, option}
}

func (e *e) ID() ac.ErrorCode {
	return e.id
}

func (e *e) Option() string {
	return e.o
}
