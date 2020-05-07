package cap

import (
	"fmt"
	"log"
	"net/http"
	"soturon/authorizer"
	"soturon/token"
	"strings"
	"sync"

	jwt "github.com/dgrijalva/jwt-go"
)

type CAEPSVC interface {
	RegisterSubscription(endpoint string, scopes string)
	InitPublish(endpoint string, token *authorizer.IntroToken, userctx *Context)
	CollectCtx(w http.ResponseWriter, r *http.Request)
}

func newCAEPSVC(issueURL string, ctxs ContextStore) CAEPSVC {
	return &caepsvc{
		rps: rps{
			db: make(map[string][]struct {
				level    string
				endpoint string
			}),
			db2: make(map[string][]string),
		},
		iss:  issueURL,
		ctxs: ctxs,
	}
}

type caepsvc struct {
	rps  rps
	iss  string
	ctxs ContextStore
}

// CAPからRPへトークンを提供するために、RPがサブスクを登録する先
func (c *caepsvc) RegisterSubscription(endpoint string, scopes string) {
	for _, scope := range strings.Split(scopes, " ") {
		if index := strings.Index(scope, ":raw"); index != -1 {
			c.rps.Save(scope[:index], "raw", endpoint)
			continue
		}
		if index := strings.Index(scope, ":predicate:"); index != -1 {
			c.rps.Save(scope[:index], scope[index+1:], endpoint)
			continue
		}
	}
}

// サブスクを登録を受けて最初のコンテキストを提供する
func (c *caepsvc) InitPublish(endpoint string, consenttoken *authorizer.IntroToken, userctx *Context) {
	events := map[string]interface{}{}
	cMap := userctx.toJSON()
	for _, scope := range strings.Split(consenttoken.Scope, " ") {
		events[scope] = cMap[scope]
	}

	c.publish(endpoint, consenttoken.UserName, events)
}

// RPがCAPへContextを送るエンドポイント用
func (c *caepsvc) CollectCtx(w http.ResponseWriter, r *http.Request) {
	setClaims, err := token.ExtractSETClaimsFrom(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed parsing seClaims %#v", err), http.StatusBadRequest)
		return
	}
	log.Printf("CAEPSVC.Subscribe succeeded %#v", setClaims)
	c.ctxs.SaveFromClaims(setClaims)
	c.prepareAndPublish(setClaims)
	w.WriteHeader(201)
	return
}

func (c *caepsvc) prepareAndPublish(claims *token.SETClaims) {
	eventPerEndpoint := make(map[string]map[string]interface{})
	v, ok := c.ctxs.Load(claims.Subject)
	if !ok {
		return
	}
	updatedctx := v.toJSON()
	log.Printf("CAEPSVC.prepareAndPublish  %#v", claims.ExtractUpdatedCtxID())
	for ctxID, _ := range claims.ExtractUpdatedCtxID() {
		for _, rpl := range c.rps.LoadRPs(ctxID) {
			v, ok := eventPerEndpoint[rpl.endpoint]
			if !ok {
				v = make(map[string]interface{})
			}
			scope := ctxID + ":" + rpl.level
			v[scope] = updatedctx[scope]
			eventPerEndpoint[rpl.endpoint] = v
		}
	}
	for endpoint, updatedctx := range eventPerEndpoint {
		if posted := c.publish(endpoint, claims.Subject, updatedctx); !posted {
			log.Printf("failed to publish to %v about %#v", endpoint, updatedctx)
		}
	}
}

func (c *caepsvc) publish(endpoint, sub string, events map[string]interface{}) bool {
	claims := &token.SETClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:   c.iss,
			Audience: endpoint,
			Subject:  sub,
		},
		Events: events,
	}
	setStr, err := claims.SignedString()
	if err != nil {
		fmt.Printf("error %#v", err)
		return false
	}
	log.Printf("cap publish to %#v about %#v", endpoint, claims)
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(setStr))
	if err != nil {
		fmt.Printf("error %#v", err)
		return false
	}
	req.Header.Set("Content-Type", "application/jwt")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("error %#v", err)
		return false
	}
	if status := resp.StatusCode; status != 201 {
		return false
	}
	return true
}

type rps struct {
	db map[string][]struct {
		level    string
		endpoint string
	} // ctxID -> {level,rpID}-array
	l   sync.RWMutex
	db2 map[string][]string // rpID -> ctxID-array
	l2  sync.RWMutex
}

func (r *rps) Save(ctxID, level, endpoint string) {
	r.l.Lock()
	defer r.l.Unlock()
	r.db[ctxID] = append(r.db[ctxID], struct {
		level    string
		endpoint string
	}{level, endpoint})

	r.l2.Lock()
	defer r.l2.Unlock()
	r.db2[endpoint] = append(r.db2[endpoint], ctxID)
}

func (r *rps) LoadRPs(ctxID string) []struct {
	level    string
	endpoint string
} {
	r.l.RLock()
	defer r.l.RUnlock()
	return r.db[ctxID]
}

func (r *rps) LoadCtxs(endpoint string) []string {
	r.l2.RLock()
	defer r.l2.RUnlock()
	return r.db2[endpoint]
}
