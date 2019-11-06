package infra

import (
	"fmt"
	"net/http"
	"net/url"
	"soturon/util"
	"sync"
)

type pef struct {
	clientConfig clientConfig
	sessions     sessionManager
}

func (p *pef) index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`
	<html><head/><body>
		<a href="http://localhost:9000/authorize">authorize</a>
	</body></html>
	`))
}

func (p *pef) redirectToAuthorizer(w http.ResponseWriter, r *http.Request) {
	client := p.clientConfig.Client(r.Context())
	sessionID := p.sessions.createID()
	p.sessions.set(sessionID, "client", client)
	http.SetCookie(w, p.sessions.createCookie(sessionID))
	client.redirectToAuthorizer(w, r)
}

type token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

func (p *pef) exchangeCodeForToken(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(p.sessions.sessionKey())
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "nothing cookie")
		return
	}

	session, ok := p.sessions.find(cookie.Value)
	if !ok {
		w.WriteHeader(400)
		fmt.Fprintf(w, "invalid cookie %#v", cookie)
		return
	}
	cc, _ := session.find("client")
	c, ok := cc.(*client)
	if !ok {
		fmt.Fprintf(w, "error: %v", cc)
	}
	c.exchangeCodeForToken(w, r)
	return
}

func (p *pef) showToken(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(p.sessions.sessionKey())
	if err != nil {
		fmt.Fprintf(w, "nothing cookie")
		return
	}
	session, ok := p.sessions.find(cookie.Value)
	if !ok {
		fmt.Fprintf(w, "invalid cookie %#v", cookie)
		return
	}
	cc, _ := session.find("client")
	if c, ok := cc.(*client); ok {
		t, _ := tokenFromContext(c.ctx)
		fmt.Fprintf(w, "Authorization: %v %v", t.TokenType, t.AccessToken)
		return
	}
	fmt.Fprintf(w, "Errrrrrr")
	return
}

func (p *pef) newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", p.index)
	mux.HandleFunc("/authorize", p.redirectToAuthorizer)
	mux.HandleFunc("/callback", p.exchangeCodeForToken)
	mux.HandleFunc("/showToken", p.showToken)
	return mux
}

func NewPEF() *http.ServeMux {
	authURL, _ := url.Parse("http://localhost:9001/authorize")
	tokenURL, _ := url.Parse("http://localhost:9001/token")
	pef := &pef{
		clientConfig: clientConfig{
			clientID:     "oauth-client-1",
			clientSecret: "oauth-client-secret-1",
			redirectURL:  "http://localhost:9000/callback",
			endpoint: authServer{
				authz: authURL,
				token: tokenURL,
			},
		},
		sessions: newSessionManager("policy-enforcement-front-session-id"),
	}
	return pef.newMux()
}

type sessionManager interface {
	sessionKey() string
	createID() string
	delete(string)
	find(string) (session, bool)
	set(sessionID, key string, value interface{}) bool
	createCookie(string) *http.Cookie
}

func newSessionManager(cookieName string) sessionManager {
	return &sesManager{
		cookieValLength: 30,
		cookieName:      cookieName,
		sessions:        make(map[string]session),
	}
}

type session map[string]interface{}

func newSession() session {
	return make(map[string]interface{})
}
func (s *session) find(key string) (interface{}, bool) {
	v, ok := (map[string]interface{}(*s))[key]
	return v, ok
}

func (s *session) set(key string, value interface{}) bool {
	(map[string]interface{}(*s))[key] = value
	return true
}

type sesManager struct {
	cookieValLength int
	cookieName      string
	sessions        map[string]session
	mux             sync.RWMutex
}

func (s *sesManager) sessionKey() string {
	return s.cookieName
}

func (s *sesManager) createID() string {
	s.mux.Lock()
	defer s.mux.Unlock()
	var sessionID string
	for ok := true; ok; {
		sessionID = util.RandString(s.cookieValLength)
		_, ok = s.sessions[sessionID]
	}
	s.sessions[sessionID] = newSession()
	return sessionID
}

func (s *sesManager) delete(sessionID string) {
	s.mux.Lock()
	defer s.mux.Unlock()
	delete(s.sessions, sessionID)
}

func (s *sesManager) find(sessionID string) (session, bool) {
	s.mux.RLock()
	defer s.mux.RUnlock()
	session, ok := s.sessions[sessionID]
	return session, ok
}

func (s *sesManager) set(sessionID, key string, value interface{}) bool {
	s.mux.RLock()
	defer s.mux.RUnlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return false
	}
	return session.set(key, value)
}

func (s *sesManager) createCookie(sessionID string) *http.Cookie {
	s.mux.RLock()
	defer s.mux.RUnlock()
	_, ok := s.sessions[sessionID]
	if !ok {
		return nil
	}
	return &http.Cookie{
		Name:  s.cookieName,
		Value: sessionID,
	}
}
