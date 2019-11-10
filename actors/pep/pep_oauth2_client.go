package pep

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"mime"
	"net/http"
	"soturon/actors/cap"
	"soturon/client"
	"soturon/ctxval"
	"soturon/session"
	"sync"
)

type OC interface {
	Authorize(w http.ResponseWriter, r *http.Request)
	Callback(w http.ResponseWriter, r *http.Request)
	HasToken(k string) bool
	FetchContext(clientKey string) (*cap.Context, bool)
}

func newOC(conf client.Config, redirectBackURL, contextURL string) OC {
	return &pepoc{
		sm: &ocSessionManager{
			Manager:    session.NewManager(),
			cookieName: "policy-enforcement-oauth2-client-session-id",
		},
		cm: &clientManager{
			conf: conf,
			db:   make(map[string]client.Client),
		},
		redirectBackURL: redirectBackURL,
		contextURL:      contextURL,
	}
}

type pepoc struct {
	sm              *ocSessionManager
	cm              *clientManager
	redirectBackURL string
	contextURL      string
}

func (p *pepoc) Authorize(w http.ResponseWriter, r *http.Request) {
	k, ok := ctxval.ClientKey(r.Context())
	if !ok {
		return
	}
	c := p.cm.create(r.Context(), k)
	sID := p.sm.UniqueID()
	p.sm.setClientKey(sID, k)
	http.SetCookie(w, &http.Cookie{Name: p.sm.cookieName, Value: sID})
	c.RedirectToAuthorizer(w, r)
}

func (p *pepoc) Callback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(p.sm.cookieName)
	if err != nil {
		return
	}
	k, ok := p.sm.getClientKey(cookie.Value)
	if !ok {
		return
	}
	c, ok := p.cm.find(k)
	if !ok {
		return
	}
	if err := c.ExchangeCodeForToken(r); err != nil {
		return
	}
	http.Redirect(w, r, p.redirectBackURL, http.StatusFound)
	return
}

func (p *pepoc) HasToken(k string) bool {
	c, ok := p.cm.find(k)
	if !ok {
		return false
	}
	return c.HasToken()
}

func (p *pepoc) FetchContext(clientKey string) (*cap.Context, bool) {
	c, ok := p.cm.find(clientKey)
	if !ok {
		return nil, false
	}
	req, err := http.NewRequest("GET", p.contextURL, nil)
	if err != nil {
		return nil, false
	}
	c.SetTokenToHeader(&req.Header)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, false
	}
	if status := resp.StatusCode; status < 200 || status >= 300 {
		return nil, false
	}
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, false
	}
	if contentType != "application/json" {
		return nil, false
	}
	actx := &cap.Context{}
	if err := json.Unmarshal(body, actx); err != nil {
		return nil, false
	}
	return actx, true
}

type ocSessionManager struct {
	session.Manager
	cookieName string
}

func (sm *ocSessionManager) setClientKey(sID, clientKey string) {
	sm.Set(sID, "clientKey", clientKey)
}

func (sm *ocSessionManager) getClientKey(sID string) (clientKey string, ok bool) {
	i, ok := sm.FindValue(sID, "clientKey")
	if !ok {
		return "", false
	}
	if clientKey, ok = i.(string); !ok {
		return "", false
	}
	return
}

type clientManager struct {
	conf client.Config
	db   map[string]client.Client
	sync.RWMutex
}

func (cm *clientManager) create(ctx context.Context, k string) client.Client {
	cm.Lock()
	defer cm.Unlock()
	c := cm.conf.Client(ctx)
	cm.db[k] = c
	return c
}

func (cm *clientManager) find(k string) (c client.Client, ok bool) {
	cm.RLock()
	defer cm.RUnlock()
	c, ok = cm.db[k]
	return
}
