package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"soturon/token"
	"soturon/util"
)

type Client interface {
	RedirectToAuthorizer(w http.ResponseWriter, r *http.Request)
	ExchangeCodeForToken(w http.ResponseWriter, r *http.Request) error
	RequestWithToken(method, url string) (*http.Request, bool)
}

func (c Config) Client(rctx RContext) Client {
	return &client{
		rctx: rctx,
		conf: c,
	}
}

type client struct {
	rctx RContext
	conf Config
}

func (c *client) RequestWithToken(method, url string) (*http.Request, bool) {
	t, ok := c.rctx.Token()
	if !ok {
		return nil, false
	}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("Authorization", t.String())
	return req, true
}

func (c *client) RedirectToAuthorizer(w http.ResponseWriter, r *http.Request) {
	state := util.RandString(12)
	c.rctx.WithState(state)
	http.Redirect(w, r, c.conf.AuthzCodeGrantURL(state), http.StatusFound)
}

func (c *client) ExchangeCodeForToken(w http.ResponseWriter, r *http.Request) error {
	code, err := c.authzCodeGrantVerify(r)
	if err != nil {
		return err
	}
	req, err := c.conf.TokenRequest(code)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	token, err := c.extractTokenFrom(resp)
	if err != nil {
		return err
	}
	c.rctx.WithToken(token)
	return nil
}

func (c *client) authzCodeGrantVerify(r *http.Request) (string, error) {
	if e := r.FormValue("error"); e != "" {
		return "", errors.New(e)
	}
	if state, ok := c.rctx.State(); !ok || state != r.FormValue("state") {
		return "", errors.New("bad state value")
	}
	code := r.FormValue("code")
	if code == "" {
		return "", errors.New("invalid code")
	}
	return code, nil
}

func (c *client) extractTokenFrom(resp *http.Response) (*token.Token, error) {
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if status := resp.StatusCode; status < 200 || status >= 300 {
		return nil,
			fmt.Errorf("status code of resp from tokenEndpoint : %v", status)
	}
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	if contentType != "application/json" {
		return nil, fmt.Errorf("not supported Content-Type: %v", contentType)
	}
	t := &token.Token{}
	if err = json.Unmarshal(body, t); err != nil {
		return nil, err
	}
	return t, nil
}
