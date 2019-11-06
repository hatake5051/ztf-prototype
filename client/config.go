package client

import (
	"net/http"
	"net/url"
	"strings"
)

type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	Endpoint     struct {
		Authz *url.URL
		Token *url.URL
	}
}

func (c *Config) AuthzCodeGrantURL(state string) string {
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {c.ClientID},
		"redirect_uri":  {c.RedirectURL},
		"state":         {state},
		"scope":         {strings.Join(c.Scopes, " ")},
	}
	authorizeURL := url.URL{
		Scheme:   "http",
		Host:     c.Endpoint.Authz.Host,
		Path:     c.Endpoint.Authz.Path,
		RawQuery: v.Encode(),
	}
	return authorizeURL.String()
}

func (c *Config) TokenRequest(code string) (*http.Request, error) {
	v := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {c.RedirectURL},
	}
	req, err := http.NewRequest("POST",
		c.Endpoint.Token.String(),
		strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type",
		"application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(c.ClientID),
		url.QueryEscape(c.ClientSecret))
	return req, nil
}
