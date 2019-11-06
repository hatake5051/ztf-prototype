package infra

import (
	"fmt"
	"log"
	"net/http"
	"soturon/client"
	"soturon/session"
	"strings"
	"sync"
)

type cap struct {
	authzConf authhorizerConfig
	sessions  session.Manager
	codes     codeManager
	tokens    map[string]*client.Token
}

func (c *cap) authorize(w http.ResponseWriter, r *http.Request) {
	authorizer := c.authzConf.instance()
	sessionID := c.sessions.UniqueID()
	c.sessions.Set(sessionID, "authorizer", authorizer)
	http.SetCookie(w, &http.Cookie{Name: "authorization-server-session-id", Value: sessionID})
	if ok := authorizer.authorize(w, r); ok {
		fmt.Fprint(w, `
		<html><head/><body>
		<form  action="/approve" method="POST">
			<input type="submit" name="approve" value="Approve">
			<input type="submit" name="deny" value="Deny">
		</form></body></html>`)
		return
	}
}

func (c *cap) approve(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("authorization-server-session-id")
	session, ok := c.sessions.Find(cookie.Value)
	if !ok {
		w.WriteHeader(400)
		fmt.Fprintf(w, "error")
		return
	}
	i, _ := session.Find("authorizer")
	a, ok := i.(*authorizer)
	if !ok {
		fmt.Fprintf(w, "invalid session")
		return
	}
	code := a.approve(w, r)
	if code == "" {
		fmt.Fprintf(w, "internal error")
		return
	}
	c.codes.register(code, a)
	return

}

func (c *cap) token(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	a, ok := c.codes.find(code)
	if !ok {
		fmt.Fprintf(w, "invalid code %v", code)
		return
	}
	c.codes.delete(code)
	t, ok := a.token(w, r)
	if !ok {
		return
	}
	c.tokens[t.AccessToken] = t
}

func (c *cap) protectedResource(w http.ResponseWriter, r *http.Request) {
	log.Printf("Authorization: %v", r.Header.Get("Authorization"))
	t := strings.Split(r.Header.Get("Authorization"), " ")
	log.Printf("%v", t)
	if _, ok := c.tokens[t[1]]; ok {
		fmt.Fprintf(w, "protected resource!!!")
		return
	}
	return

}

func (c *cap) newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", c.authorize)
	mux.HandleFunc("/token", c.token)
	mux.HandleFunc("/approve", c.approve)
	mux.HandleFunc("/resources", c.protectedResource)
	return mux
}

func NewCAP() *http.ServeMux {
	cap := &cap{
		authzConf: authhorizerConfig{
			registered: map[string]*client.Config{
				"oauth-client-1": &client.Config{
					ClientID:     "oauth-client-1",
					ClientSecret: "oauth-client-secret-1",
					RedirectURL:  "http://localhost:9000/callback",
				},
			},
		},
		sessions: session.NewManager(),
		codes:    newCodeManager(),
		tokens:   make(map[string]*client.Token),
	}
	return cap.newMux()
}

// type capRP struct {
// 	clientConfig client.Config
// 	sessions     session.Manager
// }

// func (c *capRP) redirectToAuthenticator(w http.ResponseWriter, r *http.Request) {
// 	client := c.clientConfig.Client(r.Context())
// 	sessionID := c.sessions.createID()
// 	c.sessions.setClient(sessionID, client)
// 	http.SetCookie(w, c.sessions.createCookie(sessionID))
// 	client.redirectToAuthorizer(w, r)
// }

// func (c *capRP) exchangeCodeForToken(w http.ResponseWriter, r *http.Request) {
// 	session, err := c.sessions.fromCookie(r)
// 	if err != nil {
// 		w.WriteHeader(400)
// 		fmt.Fprintf(w, "error: %v", err)
// 		return
// 	}
// 	client, ok := session.extractClient()
// 	if !ok {
// 		fmt.Fprintf(w, "invalid session")
// 		return
// 	}
// 	if ok := client.exchangeCodeForToken(w, r); ok {
// 		// TODO
// 	}
// }

type codeManager interface {
	register(code string, val *authorizer)
	delete(code string)
	find(code string) (*authorizer, bool)
}

func newCodeManager() codeManager {
	return &cManager{
		codes: make(map[string]*authorizer),
	}
}

type cManager struct {
	codes map[string]*authorizer
	mux   sync.RWMutex
}

func (c *cManager) register(code string, val *authorizer) {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.codes[code] = val
}

func (c *cManager) delete(code string) {
	c.mux.Lock()
	defer c.mux.Unlock()
	delete(c.codes, code)
}

func (c *cManager) find(code string) (*authorizer, bool) {
	c.mux.RLock()
	defer c.mux.RUnlock()
	a, ok := c.codes[code]
	return a, ok
}
