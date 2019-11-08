package client

import (
	"context"
	"net/http"
	"soturon/token"
)

type contextKey int

const (
	stateKey   contextKey = 0
	tokenKey   contextKey = 1
	idtokenKey contextKey = 2
	requestKey contextKey = 3
)

type RContext interface {
	WithState(string)
	State() (string, bool)
	WithToken(*token.Token)
	Token() (*token.Token, bool)
	WithIDToken(*token.IDToken)
	IDToken() (*token.IDToken, bool)
	WithRequest(r *http.Request)
	Request() (r *http.Request, ok bool)
	To() context.Context
}

func NewRContext(ctx context.Context) RContext {
	return &rcontext{ctx}
}

type rcontext struct {
	context.Context
}

func (rc *rcontext) To() context.Context {
	return rc.Context
}

func (rc *rcontext) WithState(state string) {
	rc.Context = context.WithValue(rc.Context, stateKey, state)
}

func (rc *rcontext) State() (state string, ok bool) {
	state, ok = rc.Context.Value(stateKey).(string)
	return
}

func (rc *rcontext) WithToken(t *token.Token) {
	rc.Context = context.WithValue(rc.Context, tokenKey, t)
}

func (rc *rcontext) Token() (t *token.Token, ok bool) {
	t, ok = rc.Context.Value(tokenKey).(*token.Token)
	return
}

func (rc *rcontext) WithIDToken(t *token.IDToken) {
	rc.Context = context.WithValue(rc.Context, idtokenKey, t)
}

func (rc *rcontext) IDToken() (t *token.IDToken, ok bool) {
	t, ok = rc.Context.Value(idtokenKey).(*token.IDToken)
	return
}

func (rc *rcontext) WithRequest(r *http.Request) {
	rc.Context = context.WithValue(rc.Context, requestKey, r)
}
func (rc *rcontext) Request() (r *http.Request, ok bool) {
	r, ok = rc.Context.Value(requestKey).(*http.Request)
	return
}
