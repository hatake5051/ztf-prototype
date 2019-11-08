package authorizer

import (
	"net/http"
	"soturon/token"
	"soturon/util"
	"strings"
	"sync"

	jwt "github.com/dgrijalva/jwt-go"
)

type TokenIssuer interface {
	Token(r *http.Request) (*token.Token, bool)
	AddCode(code string, approved map[string]string)
}

func NewTokenIssuer(registered ClientRegistration) TokenIssuer {
	return &tokenIssuer{
		registered: registered,
		codes:      &codeManager{codes: make(map[string]map[string]string)},
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
		if !ok || c["clientID"] != clientID {
			return nil, false
		}
		defer t.codes.delete(code)
		t := &token.Token{
			AccessToken: util.RandString(30),
			TokenType:   "Bearer",
			Scope:       c["scopes"],
		}
		return t, true
	}
	return nil, false
}

func (t *tokenIssuer) AddCode(code string, approved map[string]string) {
	t.codes.register(code, approved)
}

type IDTokenIssuer interface {
	IDToken(r *http.Request) (*token.IDToken, bool)
	AddCode(code string, c map[string]string)
}

func NewIDTokenIssuer(registered ClientRegistration) IDTokenIssuer {
	return &tokenIssuer{
		registered: registered,
		codes:      &codeManager{codes: make(map[string]map[string]string)},
	}
}

func (t *tokenIssuer) IDToken(r *http.Request) (*token.IDToken, bool) {
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
		if !ok || c["clientID"] != clientID {
			return nil, false
		}
		defer t.codes.delete(code)
		ok = false
		if !strings.Contains(c["scopes"], "openid") {
			return nil, false
		}
		t := &token.IDToken{
			Token: token.Token{AccessToken: util.RandString(30),
				TokenType: "Bearer",
				Scope:     c["scopes"],
			},
		}
		claims := &jwt.StandardClaims{
			Issuer:   "http://localhost:9002",
			Subject:  c["user"],
			Audience: clientID,
		}
		if err := t.Signed(claims); err != nil {
			return nil, false
		}
		return t, true
	}
	return nil, false
}

type codeManager struct {
	codes map[string]map[string]string
	mux   sync.RWMutex
}

func (c *codeManager) register(code string, v map[string]string) {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.codes[code] = v
}

func (c *codeManager) delete(code string) {
	c.mux.Lock()
	defer c.mux.Unlock()
	delete(c.codes, code)
}

func (c *codeManager) find(code string) (map[string]string, bool) {
	c.mux.RLock()
	defer c.mux.RUnlock()
	a, ok := c.codes[code]
	return a, ok
}
