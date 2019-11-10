package cap

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"mime"
	"net/http"
	"soturon/authorizer"
	"soturon/client"
	"soturon/ctxval"
	"soturon/session"
	"sync"
)

type CAPRP interface {
	Authenticate(w http.ResponseWriter, r *http.Request)
	Callback(w http.ResponseWriter, r *http.Request)
	HasIDToken(rpkey string) bool
	FetchUserInfo(rpkey string) (*authorizer.User, bool)
}

func newCAPRP(conf *client.Config, redirectBack, userInfoURL string) CAPRP {
	return &caprp{
		sm: &rpSessionManager{
			Manager:    session.NewManager(),
			cookieName: "context-attribute-oidc-relyingparty-session-id",
		},
		rm: &rpManager{
			conf: conf,
			db:   make(map[string]client.RP),
		},
		redirectBackURL: redirectBack,
		userInfoURL:     userInfoURL,
	}
}

type caprp struct {
	sm              *rpSessionManager
	rm              *rpManager
	redirectBackURL string
	userInfoURL     string
}

func (c *caprp) Authenticate(w http.ResponseWriter, r *http.Request) {
	k, ok := ctxval.RPKey(r.Context())
	if !ok {
		w.WriteHeader(501)
		return
	}
	rp := c.rm.create(r.Context(), k)
	http.SetCookie(w, c.sm.setRPKeyAndNewCookie(k))
	rp.RedirectToAuthenticator(w, r)
}

func (c *caprp) Callback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(c.sm.cookieName)
	if err != nil {
		return
	}
	k, ok := c.sm.getRPKey(cookie.Value)
	if !ok {
		return
	}
	rp, ok := c.rm.find(k)
	if !ok {
		return
	}
	if err := rp.ExchangeCodeForIDToken(r); err != nil {
		return
	}
	http.Redirect(w, r, c.redirectBackURL, http.StatusFound)
}

func (c *caprp) HasIDToken(rpKey string) bool {
	rp, ok := c.rm.find(rpKey)
	if !ok {
		return false
	}
	return rp.HasIDToken()
}

func (c *caprp) FetchUserInfo(rpKey string) (*authorizer.User, bool) {
	rp, ok := c.rm.find(rpKey)
	if !ok {
		return nil, false
	}
	req, err := http.NewRequest("GET", c.userInfoURL, nil)
	if err != nil {
		return nil, false
	}
	rp.SetIDTokenToHeader(&req.Header)
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
	user := &authorizer.User{}
	if err := json.Unmarshal(body, user); err != nil {
		return nil, false
	}
	return user, true

}

type rpSessionManager struct {
	session.Manager
	cookieName string
}

func (sm *rpSessionManager) setRPKeyAndNewCookie(rpKey string) *http.Cookie {
	sID := sm.UniqueID()
	sm.Set(sID, "rpKey", rpKey)
	return &http.Cookie{Name: sm.cookieName, Value: sID}

}

func (sm *rpSessionManager) getRPKey(sID string) (rpKey string, ok bool) {
	i, ok := sm.FindValue(sID, "rpKey")
	if !ok {
		return "", false
	}
	if rpKey, ok = i.(string); !ok {
		return "", false
	}
	return
}

type rpManager struct {
	conf *client.Config
	db   map[string]client.RP
	sync.RWMutex
}

func (rm *rpManager) create(ctx context.Context, k string) client.RP {
	rm.Lock()
	defer rm.Unlock()
	r := rm.conf.RP(ctx)
	rm.db[k] = r
	return r
}

func (rm *rpManager) find(k string) (r client.RP, ok bool) {
	rm.RLock()
	defer rm.RUnlock()
	r, ok = rm.db[k]
	return
}
