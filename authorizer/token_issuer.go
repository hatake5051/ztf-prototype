package authorizer

import (
	"net/http"
	"soturon/client"
	"soturon/token"
	"soturon/util"
	"strings"
	"sync"
)

type TokenIssuer interface {
	Token(r *http.Request) (*token.Token, bool)
	AddCode(code string, c *client.Config)
}

func NewTokenIssuer(registered ClientRegistration) TokenIssuer {
	return &tokenIssuer{
		registered: registered,
		codes:      &codeManager{codes: make(map[string]*client.Config)},
	}
}

type tokenIssuer struct {
	registered ClientRegistration
	codes      *codeManager
}

func (t *tokenIssuer) Token(r *http.Request) (*token.Token, bool) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		return nil, false
	}
	if c, ok := t.registered.Find(clientID); !ok || c.ClientSecret != clientSecret {
		return nil, false
	}
	if r.FormValue("grant_type") == "authorization_code" {
		code := r.FormValue("code")
		c, ok := t.codes.find(code)
		if !ok || c.ClientID != clientID {
			return nil, false
		}
		defer t.codes.delete(code)
		t := &token.Token{
			AccessToken: util.RandString(30),
			TokenType:   "Bearer",
			Scope:       strings.Join(c.Scopes, " "),
		}
		return t, true
	}
	return nil, false
}

func (t *tokenIssuer) AddCode(code string, c *client.Config) {
	t.codes.register(code, c)
}

type codeManager struct {
	codes map[string]*client.Config
	mux   sync.RWMutex
}

func (c *codeManager) register(code string, v *client.Config) {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.codes[code] = v
}

func (c *codeManager) delete(code string) {
	c.mux.Lock()
	defer c.mux.Unlock()
	delete(c.codes, code)
}

func (c *codeManager) find(code string) (*client.Config, bool) {
	c.mux.RLock()
	defer c.mux.RUnlock()
	a, ok := c.codes[code]
	return a, ok
}
