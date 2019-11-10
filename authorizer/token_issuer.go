package authorizer

import (
	"net/http"
	"soturon/token"
	"soturon/util"
	"strings"
	"sync"

	jwt "github.com/dgrijalva/jwt-go"
)

// TokenIssuer は アクセストークンを発行する
type TokenIssuer interface {
	// Token は リクエストを検証し、正しければトークンを発行する。
	Token(r *http.Request) (*token.Token, *TokenOptions, bool)
	// AddCode は ユーザの同意を元に発行される code を記憶するためのメソッド。
	AddCode(code string, opts *TokenOptions)
}

func NewTokenIssuer(registered ClientRegistration) TokenIssuer {
	return &tokenIssuer{
		registered: registered,
		codes:      &codeManager{codes: make(map[string]*TokenOptions)},
	}
}

type TokenOptions struct {
	ClientID string
	Scopes   []string
	User     *User
}

type tokenIssuer struct {
	registered ClientRegistration
	codes      *codeManager
}

func (t *tokenIssuer) Token(r *http.Request) (*token.Token, *TokenOptions, bool) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		return nil, nil, false
	}
	if c, ok := t.registered.Find(clientID); !ok || c.ClientSecret != clientSecret {
		return nil, nil, false
	}
	if r.FormValue("grant_type") == "authorization_code" {
		code := r.FormValue("code")
		opts, ok := t.codes.find(code)
		if !ok || opts.ClientID != clientID {
			return nil, nil, false
		}
		defer t.codes.delete(code)
		t := &token.Token{
			AccessToken: util.RandString(30),
			TokenType:   "Bearer",
			Scope:       strings.Join(opts.Scopes, " "),
		}
		return t, opts, true
	}
	return nil, nil, false
}

func (t *tokenIssuer) AddCode(code string, opts *TokenOptions) {
	t.codes.register(code, opts)
}

type IDTokenIssuer interface {
	IDToken(r *http.Request) (*token.IDToken, bool)
	AddCode(code string, opts *TokenOptions)
}

func NewIDTokenIssuer(registered ClientRegistration) IDTokenIssuer {
	return &tokenIssuer{
		registered: registered,
		codes:      &codeManager{codes: make(map[string]*TokenOptions)},
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
		opts, ok := t.codes.find(code)
		if !ok || opts.ClientID != clientID {
			return nil, false
		}
		defer t.codes.delete(code)
		ok = false
		if !strings.Contains(strings.Join(opts.Scopes, " "), "openid") {
			return nil, false
		}
		t := &token.IDToken{
			Token: token.Token{AccessToken: util.RandString(30),
				TokenType: "Bearer",
				Scope:     strings.Join(opts.Scopes, " "),
			},
		}
		claims := jwt.MapClaims{
			"iss": "http://localhost:9002",
			"sub": opts.User.Name,
			"aud": clientID,
		}
		if err := t.Signed(claims); err != nil {
			return nil, false
		}
		return t, true
	}
	return nil, false
}

type codeManager struct {
	codes map[string]*TokenOptions
	mux   sync.RWMutex
}

func (c *codeManager) register(code string, v *TokenOptions) {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.codes[code] = v
}

func (c *codeManager) delete(code string) {
	c.mux.Lock()
	defer c.mux.Unlock()
	delete(c.codes, code)
}

func (c *codeManager) find(code string) (*TokenOptions, bool) {
	c.mux.RLock()
	defer c.mux.RUnlock()
	a, ok := c.codes[code]
	return a, ok
}
