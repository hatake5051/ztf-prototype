package ctxval

import (
	"context"
	"soturon/token"
)

type contextKey int

const (
	stateKey    contextKey = 0
	tokenKey    contextKey = 1
	idtokenKey  contextKey = 2
	redirectKey contextKey = 3
	clientKey   contextKey = 4
	rpKey       contextKey = 5
)

// WithState は Oauth2.0 Client が作成した state をコンテキストに蓄積する
func WithState(ctx context.Context, state string) context.Context {
	return context.WithValue(ctx, stateKey, state)
}

// State は OAuth2.0 Client が以前に作成した state をコンテキストから取り出す。
func State(ctx context.Context) (state string, ok bool) {
	state, ok = ctx.Value(stateKey).(string)
	return
}

// WithToken は OAuth2.0 Client が Provider から取得したトークンをコンテキストに蓄積する。
func WithToken(ctx context.Context, t *token.Token) context.Context {
	return context.WithValue(ctx, tokenKey, t)
}

// Token は OAuth2.0 Client が取得しておいたトークンをコンテキストから取り出す。
func Token(ctx context.Context) (t *token.Token, ok bool) {
	t, ok = ctx.Value(tokenKey).(*token.Token)
	return
}

// WithIDToken は OIDC RP が Provider から取得したIDトークンをコンテキストに蓄積する。
func WithIDToken(ctx context.Context, t *token.IDToken) context.Context {
	return context.WithValue(ctx, idtokenKey, t)
}

// IDToken は OIDC RP が取得しておいたIDトークンをコンテキストから取り出す。
func IDToken(ctx context.Context) (t *token.IDToken, ok bool) {
	t, ok = ctx.Value(idtokenKey).(*token.IDToken)
	return
}

// WithRedirect は CAP RP がトークン取得後、どこにリダイレクトし直せば良いかをコンテキストに蓄積する。
func WithRedirect(ctx context.Context, r string) context.Context {
	return context.WithValue(ctx, redirectKey, r)
}

// Redirect は CAP RP が取得しておいた戻し先をコンテキストから取り出す。
func Redirect(ctx context.Context) (r string, ok bool) {
	r, ok = ctx.Value(redirectKey).(string)
	return
}

// WithClientKey は PEP が PEPOC の Client を識別するためのIDをセットする
func WithClientKey(ctx context.Context, k string) context.Context {
	return context.WithValue(ctx, clientKey, k)
}

// ClientKey は PEPOC が PEP の識別しを取り出すために使う
func ClientKey(ctx context.Context) (k string, ok bool) {
	k, ok = ctx.Value(clientKey).(string)
	return
}

// WithRPKey は CAP が CAPRP の RP を識別するためのIDをセットする
func WithRPKey(ctx context.Context, k string) context.Context {
	return context.WithValue(ctx, rpKey, k)
}

// RPKey は CAPRP が CAP の識別しを取り出すために使う
func RPKey(ctx context.Context) (k string, ok bool) {
	k, ok = ctx.Value(rpKey).(string)
	return
}
