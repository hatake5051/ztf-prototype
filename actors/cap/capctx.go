package cap

import (
	"encoding/json"
	"fmt"
	"soturon/token"
	"sync"
)

type Context struct {
	UserAgent                  string `json:"device:useragent:raw,omitempty"`
	UserAgentHaveBeenUsed      bool   `json:"device:useragent:predicate:recentlyused"`
	UserLocation               string `json:"user:location:raw,omitempty"`
	UserLocationHaveBeenStayed bool   `json:"user:location:predicate:recentlystayed"`
	UserLocationIsJapan        bool   `json:"user:location:predicate:isjapan"`
}

func (c *Context) toJSON() map[string]interface{} {
	cJSON, err := json.Marshal(c)
	if err != nil {
		panic("arien")
	}
	var cMap map[string]interface{}
	if err := json.Unmarshal(cJSON, &cMap); err != nil {
		panic("arien")
	}
	return cMap
}
func fromJSON(cMap map[string]interface{}) (*Context, error) {
	cJSON, err := json.Marshal(cMap)
	if err != nil {
		return nil, err
	}
	var ret Context
	if err := json.Unmarshal(cJSON, &ret); err != nil {
		return nil, err
	}
	return &ret, nil
}

func (c *Context) Filtered(scopes []string) Context {
	cMap := c.toJSON()
	filtered := make(map[string]interface{})
	for _, scope := range scopes {
		filtered[scope] = cMap[scope]
	}
	ret, err := fromJSON(filtered)
	if err != nil {
		return Context{}
	}
	return *ret
}

type ContextStore interface {
	Save(userID string, userctx *Context)
	SaveFromClaims(claims *token.SETClaims)
	Load(userID string) (*Context, bool)
}

func NewCtxStore() ContextStore {
	return &ctxStore{
		db: make(map[string]Context),
	}
}

type ctxStore struct {
	db map[string]Context
	l  sync.RWMutex
}

func (c *ctxStore) Save(userID string, userctx *Context) {
	c.l.Lock()
	defer c.l.Unlock()
	ctxs, ok := c.db[userID]
	if !ok {
		ctxs = Context{}
	}
	now := ctxs.toJSON()
	updated := userctx.toJSON()
	k := "device:useragent:raw"
	if _, ok := updated[k]; ok {
		k2 := "device:useragent:predicate:recentlyused"
		if !now[k2].(bool) {
			if nowk2, ok := now[k].(string); ok {
				now[k2] = (nowk2 == updated[k].(string))
			} else {
				now[k2] = false
			}
		}
		now[k] = updated[k]
	} else {
		k = "device:useragent:predicate:recentlyused"
		if _, ok := updated[k]; ok {
			now[k] = updated[k]
		}
	}
	k = "user:location:raw"
	if _, ok := updated[k]; ok {
		k2 := "user:location:predicate:recentlystayed"
		if !now[k2].(bool) {
			if nowk2, ok := now[k].(string); ok {
				now[k2] = (nowk2 == updated[k].(string))
			} else {
				now[k2] = false
			}
		}
		now[k] = updated[k]
		k2 = "user:location:predicate:isjapan"
		now[k2] = (updated[k].(string) == "ja")
	} else {
		k = "user:location:predicate:recentlystayed"
		if _, ok := updated[k]; ok {
			now[k] = updated[k]
		}
		k = "user:location:predicate:isjapan"
		if _, ok := updated[k]; ok {
			now[k] = updated[k]
		}
	}
	nowctx, err := fromJSON(now)
	if err != nil {
		panic(fmt.Sprintf("bikkuri %#v", now))
	}
	c.db[userID] = *nowctx
}

func (c *ctxStore) SaveFromClaims(claims *token.SETClaims) {
	updatectx, err := fromJSON(claims.Events)
	if err != nil {
		return
	}
	c.Save(claims.Subject, updatectx)
}

func (c *ctxStore) Load(userID string) (*Context, bool) {
	c.l.RLock()
	defer c.l.RUnlock()
	ctx, ok := c.db[userID]
	return &ctx, ok
}

func find(l []string, x string) bool {
	for _, s := range l {
		if s == x {
			return true
		}
	}
	return false
}
