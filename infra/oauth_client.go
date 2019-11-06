package infra

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"soturon/util"
	"strings"
)

type authServer struct {
	authz *url.URL
	token *url.URL
}

type clientConfig struct {
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       []string
	endpoint     authServer
}

func (cc *clientConfig) authzCodeURL(state string) string {
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {cc.clientID},
		"redirect_uri":  {cc.redirectURL},
		"state":         {state},
	}
	authorizeURL := url.URL{
		Scheme:   "http",
		Host:     cc.endpoint.authz.Host,
		Path:     cc.endpoint.authz.Path,
		RawQuery: v.Encode(),
	}
	return authorizeURL.String()
}

func (cc *clientConfig) tokenRequest(code string) (*http.Request, error) {
	v := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {cc.redirectURL},
	}
	req, err := http.NewRequest("POST", cc.endpoint.token.String(), strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(cc.clientID), url.QueryEscape(cc.clientSecret))
	return req, nil
}

func (cc *clientConfig) Client(ctx context.Context) *client {
	return &client{
		ctx:  ctx,
		conf: cc,
	}
}

type client struct {
	ctx  context.Context
	conf *clientConfig
}

func (c *client) redirectToAuthorizer(w http.ResponseWriter, r *http.Request) {
	state := util.RandString(12)
	c.ctx = contextWithState(c.ctx, state)
	http.Redirect(w, r, c.conf.authzCodeURL(state), http.StatusFound)
}

type stateKey int

const defaultStateKey stateKey = 0

func contextWithState(ctx context.Context, state string) context.Context {
	return context.WithValue(ctx, defaultStateKey, state)
}

func stateFromContext(ctx context.Context) (string, bool) {
	state, ok := ctx.Value(defaultStateKey).(string)
	return state, ok
}

func (c *client) authzCodeVerification(r *http.Request) (bool, int, string) {
	if e := r.FormValue("error"); e != "" {
		return false, 400, "authorize error: " + e
	}
	state := r.FormValue("state")
	if expect, ok := stateFromContext(c.ctx); !ok || expect != state {
		return false, 400, fmt.Sprintf("bad state value: %v expect: %v", state, expect)
	}
	code := r.FormValue("code")
	if code == "" {
		return false, 401, "code in request is empty"
	}
	return true, 0, ""
}

func (c *client) extractTokenFrom(resp *http.Response) (*token, bool, string) {
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Sprintf("when resp.Body reading: %v", err)
	}
	if status := resp.StatusCode; status < 200 || status >= 300 {
		return nil, false, fmt.Sprintf("status code of resp from tokenEndpoint : %v", status)
	}
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, false, fmt.Sprintf("mime.parseMediaType error: %v", err)

	}
	if contentType != "application/json" {
		return nil, false, fmt.Sprintf("not supported content-type: %v", contentType)
	}
	var t = &token{}
	if err = json.Unmarshal(body, t); err != nil {
		return nil, false, fmt.Sprintf("json parse failed %v", err)
	}
	return t, true, ""
}

func (c *client) exchangeCodeForToken(w http.ResponseWriter, r *http.Request) {
	if ok, statusCode, message := c.authzCodeVerification(r); !ok {
		w.WriteHeader(statusCode)
		fmt.Fprintf(w, message)
		return
	}
	req, err := c.conf.tokenRequest(r.FormValue("code"))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "server internal error: %v", err)
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "request to tokenEndpoint error: %v", err)
		return
	}
	token, ok, message := c.extractTokenFrom(resp)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, message)
		return
	}
	c.ctx = contextWithToken(c.ctx, token)
	fmt.Fprint(w, `
	<html><head/><body>
	大成功
	</body></html>`)
}

type tokenKey int

const defaultTokenKey tokenKey = 0

func contextWithToken(ctx context.Context, token *token) context.Context {
	return context.WithValue(ctx, defaultTokenKey, token)
}

func tokenFromContext(ctx context.Context) (*token, bool) {
	token, ok := ctx.Value(defaultTokenKey).(*token)
	return token, ok
}
