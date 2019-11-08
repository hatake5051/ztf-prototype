package client

import (
	"context"
	"soturon/token"

	"github.com/dgrijalva/jwt-go"
)

type contextKey int

const (
	stateKey   contextKey = 0
	tokenKey   contextKey = 1
	idtokenKey contextKey = 2
)

type RContext interface {
	WithState(string)
	State() (string, bool)
	WithToken(*token.Token)
	Token() (*token.Token, bool)
	WithIDToken(*jwt.Token)
	IDToken() (*jwt.Token, bool)
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

func (rc *rcontext) WithToken(t *token.Token) {
	rc.Context = context.WithValue(rc.Context, tokenKey, t)
}

func (rc *rcontext) Token() (t *token.Token, ok bool) {
	t, ok = rc.Context.Value(tokenKey).(*token.Token)
	return
}

func (rc *rcontext) WithIDToken(t *jwt.Token) {
	rc.Context = context.WithValue(rc.Context, idtokenKey, t)
}

func (rc *rcontext) IDToken() (t *jwt.Token, ok bool) {
	t, ok = rc.Context.Value(idtokenKey).(*jwt.Token)
	return
}
