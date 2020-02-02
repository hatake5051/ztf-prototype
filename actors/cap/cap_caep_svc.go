package cap

import (
	"encoding/json"
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

func (c *caepsvc) RegisterSubscription(endpoint string, scopes string) {
	log.Printf("scopes : %#v", scopes)
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

func (c *caepsvc) InitPublish(endpoint string, consenttoken *authorizer.IntroToken, userctx *Context) {
	events := map[string]interface{}{}
	cJSON, err := json.Marshal(userctx)
	if err != nil {
		panic("arien")
	}
	var cMap map[string]interface{}
	if err := json.Unmarshal(cJSON, &cMap); err != nil {
		panic("arien")
	}
	for _, scope := range strings.Split(consenttoken.Scope, " ") {
		if index := strings.Index(scope, ":raw"); index != -1 {
			events[scope] = cMap[scope[:index]]
			continue
		}
		if index := strings.Index(scope, ":predicate:"); index != -1 {
			log.Printf("createPublishingEvents predicate not impl %#v", scope)
			continue
		}
	}

	c.publish(endpoint, consenttoken.UserName, events)
}

func (c *caepsvc) CollectCtx(w http.ResponseWriter, r *http.Request) {
	setClaims, err := token.ExtractSETClaimsFrom(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed parsing seClaims %#v", err), http.StatusBadRequest)
		return
	}
	log.Printf("CAEPSVC.Subscribe succeeded %#v", setClaims)
	c.collectSETandPublish(setClaims)
	w.WriteHeader(201)
	return
}

func (c *caepsvc) collectSETandPublish(claims *token.SETClaims) {
	c.ctxs.Update(claims)
	events := claims.Events
	publishqueue := make(map[string][]struct {
		ctxid, level string
		ctx          interface{}
	})
	for eventID, value := range events {
		var ctxID string
		if index := strings.Index(eventID, ":raw"); index != -1 {
			ctxID = eventID[:index]
		} else if index := strings.Index(eventID, ":predicate:"); index != -1 {
			panic("collect set ctx must be raw-level")
		}
		for _, rpl := range c.rps.LoadRPs(ctxID) {
			publishqueue[rpl.endpoint] = append(publishqueue[rpl.endpoint], struct {
				ctxid string
				level string
				ctx   interface{}
			}{ctxID, rpl.level, value})
		}
	}

	for endpoint, updatedctx := range publishqueue {
		events := createPublishingEvents(updatedctx)
		if posted := c.publish(endpoint, claims.Subject, events); !posted {
			log.Printf("failed to publish to %v about %#v", endpoint, events)
		}
	}
}

func createPublishingEvents(updatedctx []struct {
	ctxid, level string
	ctx          interface{}
}) map[string]interface{} {
	events := make(map[string]interface{})
	for _, s := range updatedctx {
		if strings.Contains(s.level, "raw") {
			events[s.ctxid+s.level] = s.ctx
			continue
		}
		if strings.Contains(s.level, "predicate") {
			log.Printf("createPublishingEvents preficate not impl %#v", s)
			continue
		}
	}
	return events
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
