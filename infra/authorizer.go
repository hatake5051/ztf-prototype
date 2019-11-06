package infra

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"soturon/client"
	"soturon/util"
)

type authhorizerConfig struct {
	registered map[string]*client.Config
}

func (ac *authhorizerConfig) verifiedClient(r *http.Request) (*client.Config, error) {
	client, ok := ac.registered[r.FormValue("client_id")]
	if !ok {
		return nil, fmt.Errorf("nothing client[%v]", r.FormValue("client_id"))
	}
	if client.RedirectURL != r.FormValue("redirect_uri") {
		return nil, fmt.Errorf("redirect no match %v %v", client.RedirectURL, r.FormValue("redirect_uri"))
	}
	return client, nil
}

func (ac *authhorizerConfig) instance() *authorizer {
	return &authorizer{
		ctx:  authorizerContext{},
		conf: ac,
	}
}

type authorizer struct {
	ctx  authorizerContext
	conf *authhorizerConfig
}

func (a *authorizer) authorize(w http.ResponseWriter, r *http.Request) bool {
	c, err := a.conf.verifiedClient(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "%v", err)
		return false
	}
	a.ctx.WithClient(c)
	a.ctx.WithState(r.FormValue("state"))
	a.ctx.WithResponseType(r.FormValue("response_type"))
	if err := a.ctx.WithRedirectURL(r.FormValue("redirect_uri")); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "%v", err)
		return false
	}
	return true
}

func (a *authorizer) approve(w http.ResponseWriter, r *http.Request) string {
	r.ParseForm()
	if r.FormValue("approve") != "Approve" {
		fmt.Fprintf(w, "access denied")
		return ""
	}

	if resType, ok := a.ctx.ExtractResponseType(); !ok || resType != "code" {
		fmt.Fprintf(w, "unsupported response type %v", resType)
		return ""
	}
	a.ctx.WithCode()
	redirectURL, _ := a.ctx.ExtractRedirectURL()
	code, _ := a.ctx.ExtractCode()
	state, _ := a.ctx.ExtractState()
	redirectURL.RawQuery = url.Values{
		"code": {code}, "state": {state},
	}.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
	return code
}

func (a *authorizer) token(w http.ResponseWriter, r *http.Request) (*client.Token, bool) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		w.WriteHeader(401)
		fmt.Fprintf(w, "no credential")
		return nil, false
	}
	if a.conf.registered[clientID].ClientSecret != clientSecret {
		w.WriteHeader(401)
		fmt.Fprintf(w, "bad credentials %v %v", clientID, clientSecret)
		return nil, false
	}
	if r.FormValue("grant_type") == "authorization_code" {
		c := a.ctx.client
		if c.ClientID != clientID {
			w.WriteHeader(400)
			fmt.Fprintf(w, "bad request parameter %#v", c)
			return nil, false
		}
		t := &client.Token{
			AccessToken: "ACCESS_TOKEN_" + util.RandString(20),
			TokenType:   "Bearer",
		}
		tJSON, err := json.Marshal(t)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(w, "serverinternalerror %v", err)
			return nil, false
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(tJSON)
		return t, true
	}
	return nil, false
}

type authorizerContext struct {
	client       *client.Config
	state        string
	responseType string
	code         string
	redirectURL  *url.URL
}

func (a *authorizerContext) WithClient(clientConfig *client.Config) {
	a.client = clientConfig
}

func (a *authorizerContext) ExtractClient() (*client.Config, bool) {
	if a.client == nil {
		return nil, false
	}
	return a.client, true
}

func (a *authorizerContext) WithCode() {
	a.code = util.RandString(12)
}

func (a *authorizerContext) ExtractCode() (string, bool) {
	if a.code == "" {
		return "", false
	}
	return a.code, true
}

func (a *authorizerContext) WithState(state string) {
	a.state = state
}

func (a *authorizerContext) ExtractState() (string, bool) {
	if a.state == "" {
		return "", false
	}
	return a.state, true
}

func (a *authorizerContext) WithResponseType(responseType string) {
	a.responseType = responseType
}

func (a *authorizerContext) ExtractResponseType() (string, bool) {
	if a.responseType == "" {
		return "", false
	}
	return a.responseType, true
}

func (a *authorizerContext) WithRedirectURL(escapedURL string) error {
	rawURL, err := url.PathUnescape(escapedURL)
	if err != nil {
		return err
	}
	url, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	a.redirectURL = url
	return nil
}

func (a *authorizerContext) ExtractRedirectURL() (*url.URL, bool) {
	if a.redirectURL == nil {
		return nil, false
	}
	return a.redirectURL, true
}
