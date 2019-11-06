package infra

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"soturon/util"
)

type cap struct {
	clients  map[string]clientConfig
	requests map[string]*http.Request
	codes    map[string]clientConfig
}

func (c *cap) authorize(w http.ResponseWriter, r *http.Request) {
	client, ok := c.clients[r.FormValue("client_id")]
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Printf("nothing client[%v]", r.FormValue("client_id"))
		return
	}
	if client.redirectURL != r.FormValue("redirect_uri") {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Printf("redirect no match %v %v", client.redirectURL, r.FormValue("redirect_uri"))
		return
	}

	var reqid = util.RandString(8)
	c.requests[reqid] = r
	fmt.Fprintf(w, `
	<html><head/><body>
	<form  action="/approve" method="POST">
		<input type="hidden" name="reqid" value="%v">
		<input type="submit" name="approve" value="Approve">
		<input type="submit" name="deny" value="Deny">
	</form></body></html>`, reqid)
	return
}

func (c *cap) approve(w http.ResponseWriter, r *http.Request) {
	reqid := r.FormValue("reqid")
	prevr, ok := c.requests[reqid]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Printf("nothing requests[%v]", r.FormValue("reqid"))
		return
	}
	if "Approve" != r.FormValue("approve") {
		fmt.Fprintf(w, "access denied")
		return
	}
	if prevr.FormValue("response_type") == "code" {
		code := util.RandString(12)
		c.codes[code] = c.clients[prevr.FormValue("client_id")]

		unescape, err := url.PathUnescape(prevr.FormValue("redirect_uri"))
		if err != nil {
			fmt.Fprintf(w, " (%v) %v", prevr.FormValue("redirect_uri"), err)
		}
		callbackURL, err := url.Parse(unescape)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "redirect_uri %v", r.FormValue("redirect_uri"))
			return
		}
		v := url.Values{
			"code":  {code},
			"state": {prevr.FormValue("state")},
		}
		callbackURL.RawQuery = v.Encode()
		http.Redirect(w, r, callbackURL.String(), http.StatusFound)
	}
}

func (c *cap) token(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		w.WriteHeader(401)
		fmt.Fprintf(w, "no credential")
		return
	}
	if c.clients[clientID].clientSecret != clientSecret {
		w.WriteHeader(401)
		fmt.Fprintf(w, "bad credentials %v %v", clientID, clientSecret)
		return
	}
	if r.FormValue("grant_type") == "authorization_code" {
		client := c.codes[r.FormValue("code")]
		if client.clientID != clientID {
			w.WriteHeader(400)
			fmt.Fprintf(w, "bad request parameter %v", c.codes[r.FormValue("code")])
			return
		}
		t := &token{
			AccessToken: "ACCESS_TOKEN_" + util.RandString(20),
			TokenType:   "Bearer",
		}
		tJSON, err := json.Marshal(t)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(w, "serverinternalerror %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(tJSON)
		return
	}
}

func (c *cap) newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", c.authorize)
	mux.HandleFunc("/token", c.token)
	mux.HandleFunc("/approve", c.approve)
	return mux
}

func NewCAP() *http.ServeMux {
	cap := &cap{
		clients: map[string]clientConfig{
			"oauth-client-1": clientConfig{
				clientID:     "oauth-client-1",
				clientSecret: "oauth-client-secret-1",
				redirectURL:  "http://localhost:9000/callback",
			},
		},
		requests: make(map[string]*http.Request),
		codes:    make(map[string]clientConfig),
	}
	return cap.newMux()
}
