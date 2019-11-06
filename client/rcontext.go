package client

import "context"

type contextKey int

const (
	stateKey contextKey = 0
	tokenKey contextKey = 1
)

type RContext interface {
	WithState(string)
	State() (string, bool)
	WithToken(*Token)
	Token() (*Token, bool)
}

func NewRContext(ctx context.Context) RContext {
	return &rcontext{ctx}
}

type rcontext struct {
	context.Context
}

func (rc *rcontext) WithState(state string) {
	rc.Context = context.WithValue(rc.Context, stateKey, state)
}

func (rc *rcontext) State() (state string, ok bool) {
	state, ok = rc.Context.Value(stateKey).(string)
	return
}

func (rc *rcontext) WithToken(t *Token) {
	rc.Context = context.WithValue(rc.Context, tokenKey, t)
}

func (rc *rcontext) Token() (t *Token, ok bool) {
	t, ok = rc.Context.Value(tokenKey).(*Token)
	return
}
