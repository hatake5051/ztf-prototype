package pep

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"soturon/actors/cap"
	"soturon/token"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

type CAEPRP interface {
	Subscribe(w http.ResponseWriter, r *http.Request)
	CollextCtx(sub string, updatedCtx *cap.Context) bool
}

func newCAEPRP(iss, publishEndpoint string) CAEPRP {
	return &caeprp{iss, publishEndpoint}
}

type caeprp struct {
	iss             string
	publishEndpoint string
}

func (c *caeprp) Subscribe(w http.ResponseWriter, r *http.Request) {
	setClaims, err := token.ExtractSETClaimsFrom(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed parsing seClaims %#v", err), http.StatusBadRequest)
		return
	}
	log.Printf("Subscribe succeeded %#v", setClaims)
	w.WriteHeader(201)
	return
}

func (c *caeprp) CollextCtx(sub string, updatedCtx *cap.Context) bool {
	events := createPublishingEvents(updatedCtx)
	return c.publish(sub, events)
}

func createPublishingEvents(updatedctx *cap.Context) map[string]interface{} {
	events := make(map[string]interface{})
	cJSON, err := json.Marshal(updatedctx)
	if err != nil {
		panic("arien")
	}
	var cMap map[string]interface{}
	if err := json.Unmarshal(cJSON, &cMap); err != nil {
		panic("arien")
	}
	for key, v := range cMap {
		events[key+":raw"] = v
	}
	return events
}

func (c *caeprp) publish(sub string, events map[string]interface{}) bool {
	claims := &token.SETClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:   c.iss,
			Audience: c.publishEndpoint,
			Subject:  sub,
		},
		Events: events,
	}
	setStr, err := claims.SignedString()
	if err != nil {
		fmt.Printf("error %#v", err)
		return false
	}
	req, err := http.NewRequest("POST", c.publishEndpoint, strings.NewReader(setStr))
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
