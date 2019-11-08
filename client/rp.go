package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"soturon/token"
)

type RP interface {
	RedirectToAuthenticator(w http.ResponseWriter, r *http.Request)
	ExchangeCodeForIDToken(r *http.Request) error
	Context() context.Context
}

func (c Config) RP(rctx RContext) RP {
	return &client{
		rctx: rctx,
		conf: c,
	}
}

func (rp *client) RedirectToAuthenticator(w http.ResponseWriter, r *http.Request) {
	rp.RedirectToAuthorizer(w, r)
}

func (rp *client) ExchangeCodeForIDToken(r *http.Request) error {
	code, err := rp.authzCodeGrantVerify(r)
	if err != nil {
		return err
	}
	req, err := rp.conf.TokenRequest(code)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	t, err := rp.extractTokenWithIDFrom(resp)
	if err != nil {
		return err
	}
	if err := t.ParseIDToken(); err != nil {
		return err
	}
	rp.rctx.WithIDToken(t)
	return nil
}

func (rp *client) extractTokenWithIDFrom(resp *http.Response) (*token.IDToken, error) {
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
	t := &token.IDToken{}
	if err = json.Unmarshal(body, t); err != nil {
		return nil, err
	}
	return t, nil
}
