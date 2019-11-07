package authorizer

import (
	"errors"
	"soturon/token"
	"sync"
)

type TokenStore interface {
	Add(*token.Token) error
	Find(string) (*token.Token, error)
	Delete(string) error
}

func NewTokenStore() TokenStore {
	return &tokenStore{
		tokens: make(map[string]*token.Token),
	}
}

type tokenStore struct {
	tokens map[string]*token.Token
	sync.RWMutex
}

func (ts *tokenStore) Add(t *token.Token) error {
	ts.Lock()
	defer ts.Unlock()
	if t == nil {
		return errors.New("parameter *token.Token is nil pointer")
	}
	ts.tokens[t.AccessToken] = t
	return nil
}

func (ts *tokenStore) Find(t string) (*token.Token, error) {
	ts.RLock()
	defer ts.RUnlock()
	tt, ok := ts.tokens[t]
	if !ok {
		return nil, errors.New("error")
	}
	return tt, nil
}

func (ts *tokenStore) Delete(t string) error {
	ts.Lock()
	defer ts.Unlock()
	delete(ts.tokens, t)
	return nil
}
