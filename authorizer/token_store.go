package authorizer

import (
	"errors"
	"soturon/token"
	"sync"
)

type TokenStore interface {
	Add(t *token.Token, options map[string]string) error
	Find(string) (*token.Token, map[string]string, error)
	Delete(string) error
}

func NewTokenStore() TokenStore {
	return &tokenStore{
		tokens: make(map[string]struct {
			t *token.Token
			o map[string]string
		}),
	}
}

type tokenStore struct {
	tokens map[string]struct {
		t *token.Token
		o map[string]string
	}
	sync.RWMutex
}

func (ts *tokenStore) Add(t *token.Token, options map[string]string) error {
	ts.Lock()
	defer ts.Unlock()
	if t == nil {
		return errors.New("parameter *token.Token is nil pointer")
	}
	ts.tokens[t.AccessToken] = struct {
		t *token.Token
		o map[string]string
	}{t: t, o: options}
	return nil
}

func (ts *tokenStore) Find(t string) (*token.Token, map[string]string, error) {
	ts.RLock()
	defer ts.RUnlock()
	tt, ok := ts.tokens[t]
	if !ok {
		return nil, nil, errors.New("error")
	}
	return tt.t, tt.o, nil
}

func (ts *tokenStore) Delete(t string) error {
	ts.Lock()
	defer ts.Unlock()
	delete(ts.tokens, t)
	return nil

}

type IDTokenStore interface {
	Add(*token.IDToken) error
	Find(string) (*token.IDToken, error)
	Delete(string) error
}

func NewIDTokenStore() IDTokenStore {
	return &idtokenStore{
		tokens: make(map[string]*token.IDToken),
	}
}

type idtokenStore struct {
	tokens map[string]*token.IDToken
	sync.RWMutex
}

func (ts *idtokenStore) Add(t *token.IDToken) error {
	ts.Lock()
	defer ts.Unlock()
	if t == nil {
		return errors.New("parameter *token.Token is nil pointer")
	}
	ts.tokens[t.AccessToken] = t
	return nil
}

func (ts *idtokenStore) Find(t string) (*token.IDToken, error) {
	ts.RLock()
	defer ts.RUnlock()
	tt, ok := ts.tokens[t]
	if !ok {
		return nil, errors.New("error")
	}
	return tt, nil
}

func (ts *idtokenStore) Delete(t string) error {
	ts.Lock()
	defer ts.Unlock()
	delete(ts.tokens, t)
	return nil

}
