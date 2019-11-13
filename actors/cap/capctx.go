package cap

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
)

type Context struct {
	IPAddr                 string   `json:"ipaddr"`
	HaveBeenUsedThisIPAddr bool     `json:"have_been_used_this_ipaddr"`
	ipaddrs                []string `json:"-"`
	UserAgent              string   `json:"useragent"`
	HaveBeenUsedThisUA     bool     `json:"have_been_used_this_useragent"`
	uas                    []string `json:"-"`
}

func (c Context) Filtered(scopes []string) Context {
	cJSON, err := json.Marshal(c)
	if err != nil {
		return c
	}
	var cMap map[string]interface{}
	log.Print(string(cJSON))
	if err := json.Unmarshal(cJSON, &cMap); err != nil {
		return c
	}
	filtered := make(map[string]interface{})
	for _, scope := range scopes {
		filtered[scope] = cMap[scope]
		filtered["have_been_used_this_"+scope] = cMap["have_been_used_this_"+scope]
	}
	cJSON, err = json.Marshal(filtered)
	if err != nil {
		return c
	}
	var ans Context
	if err := json.Unmarshal(cJSON, &ans); err != nil {
		return c
	}
	return ans
}

type ContextStore interface {
	Save(userID string, r *http.Request)
	Load(userID string) (*Context, bool)
}

func NewCtxStore() ContextStore {
	return &ctxStore{
		db: make(map[string]*Context),
	}
}

type ctxStore struct {
	db map[string]*Context
	l  sync.RWMutex
}

func (c *ctxStore) Save(userID string, r *http.Request) {
	c.l.Lock()
	defer c.l.Unlock()
	ctx, ok := c.db[userID]
	if !ok {
		ctx = new(Context)
	}

	ipaddr := r.RemoteAddr
	ctx.IPAddr = ipaddr
	log.Printf("ipaddresss: %#v, ipaddr: %#v", ctx.ipaddrs, ipaddr)
	if find(ctx.ipaddrs, ipaddr) {
		ctx.HaveBeenUsedThisIPAddr = true
	} else {
		ctx.HaveBeenUsedThisIPAddr = false
	}
	ctx.ipaddrs = append(ctx.ipaddrs, ipaddr)
	ua := r.UserAgent()
	ctx.UserAgent = ua
	if find(ctx.uas, ua) {
		ctx.HaveBeenUsedThisUA = true
	} else {
		ctx.HaveBeenUsedThisUA = false
	}
	log.Printf("Save ctx: %#v", ctx)
	ctx.uas = append(ctx.uas, ua)
	c.db[userID] = ctx
}

func (c *ctxStore) Load(userID string) (ctx *Context, ok bool) {
	c.l.RLock()
	defer c.l.RUnlock()
	ctx, ok = c.db[userID]
	return
}

func find(l []string, x string) bool {
	for _, s := range l {
		if s == x {
			return true
		}
	}
	return false
}
