package infra

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"mime"
	"net/http"
	"net/url"
	"soturon/util"
	"strings"
	"sync"
)

type authzServer struct {
	authzEndpoint *url.URL
	tokenEndpoint *url.URL
}

type clientConfig struct {
	clientID     string
	clientSecret string
	redirectURL  string
}

type pef struct {
	authzServer  authzServer
	clientConfig clientConfig
	states       stateManager
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
	state := p.states.create()
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {p.clientConfig.clientID},
		"redirect_uri":  {p.clientConfig.redirectURL},
		"state":         {state},
	}
	authorizeURL := url.URL{
		Scheme:   "http",
		Host:     p.authzServer.authzEndpoint.Host,
		Path:     p.authzServer.authzEndpoint.Path,
		RawQuery: v.Encode(),
	}
	http.Redirect(w, r, authorizeURL.String(), http.StatusFound)
}

type token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

func (p *pef) exchangeCodeForToken(w http.ResponseWriter, r *http.Request) {
	if e := r.FormValue("error"); e != "" {
		fmt.Fprintf(w, "%v", e)
		return
	}
	state := r.FormValue("state")
	if !p.states.find(state) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "bad state value: %v", state)
		return
	}
	p.states.delete(state)
	code := r.FormValue("code")
	if code == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "code in request is empty")
		return
	}
	v := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {p.clientConfig.redirectURL},
	}
	req, err := http.NewRequest("POST", p.authzServer.tokenEndpoint.String(), strings.NewReader(v.Encode()))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "server internal error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(p.clientConfig.clientID), url.QueryEscape(p.clientConfig.clientSecret))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "request to tokenEndpoint error: %v", err)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "error: %v", err)
		return
	}
	if status := resp.StatusCode; status < 200 || status >= 300 {
		w.WriteHeader(status)
		fmt.Fprintf(w, "error: %v", status)
		return
	}
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "mime.parsemedia error: %v", err)
		return
	}
	if contentType != "application/json" {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "not supported content-type: %v", contentType)
		return
	}
	var t = &token{}
	if err = json.Unmarshal(body, t); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "json parse failed %v", body)
		return
	}

	sessionID := p.sessions.createID()
	p.sessions.set(sessionID, "token", t)
	http.SetCookie(w, p.sessions.createCookie(sessionID))

	fmt.Fprint(w, `
	<html><head/><body>
	<a href="/showToken">show token</a>
	</body></html>`)
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
	t, _ := session.find("token")
	log.Printf("%T", t)
	if t, ok := t.(*token); ok {
		fmt.Fprintf(w, "Authorization: %v %v", t.TokenType, t.AccessToken)
		return
	}

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
		authzServer: authzServer{
			authzEndpoint: authURL,
			tokenEndpoint: tokenURL,
		},
		clientConfig: clientConfig{
			clientID:     "oauth-client-1",
			clientSecret: "oauth-client-secret-1",
			redirectURL:  "http://localhost:9000/callback",
		},
		states:   newStateManager(12),
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

type stateManager interface {
	create() string
	delete(string)
	find(string) bool
}

func newStateManager(stateLength int) stateManager {
	return &sManager{
		stateLength: stateLength,
		states:      make(map[string]bool),
	}
}

type sManager struct {
	stateLength int
	states      map[string]bool
	mux         sync.RWMutex
}

func (s *sManager) create() string {
	s.mux.Lock()
	defer s.mux.Unlock()
	state := util.RandString(s.stateLength)
	for s.states[state] {
		state = util.RandString(s.stateLength)
	}
	s.states[state] = true
	return state
}

func (s *sManager) delete(state string) {
	s.mux.Lock()
	defer s.mux.Unlock()
	delete(s.states, state)

}

func (s *sManager) find(state string) bool {
	s.mux.RLock()
	defer s.mux.RUnlock()
	return s.states[state]
}
