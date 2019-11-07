package infra

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"soturon/authorizer"
	"soturon/client"
	"strings"
)

type cap struct {
	authorizer.Authorizer
}

func (c *cap) protectedResource(w http.ResponseWriter, r *http.Request) {
	t := strings.Split(r.Header.Get("Authorization"), " ")
	req, err := http.NewRequest("POST", "http://localhost:9001/introspect",
		strings.NewReader(url.Values{"token": {t[1]}}.Encode()))
	if err != nil {
		fmt.Fprintf(w, "cannot create request")
		return
	}
	req.Header.Set("Content-Type",
		"application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(w, "cannot communicate with introspect endpoint")
		return
	}
	defer resp.Body.Close()
	b, _ := ioutil.ReadAll(resp.Body)
	w.Write(b)
	return
}

func (c *cap) newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", c.Authorize)
	mux.HandleFunc("/token", c.IssueToken)
	mux.HandleFunc("/approve", c.Approve)
	mux.HandleFunc("/introspect", c.IntroSpect)
	mux.HandleFunc("/resources", c.protectedResource)
	return mux
}

func NewCAP() *http.ServeMux {
	cap := &cap{
		Authorizer: authorizer.New(map[string]*client.Config{
			"oauth-client-1": &client.Config{
				ClientID:     "oauth-client-1",
				ClientSecret: "oauth-client-secret-1",
				RedirectURL:  "http://localhost:9000/callback",
			}},
		),
	}
	return cap.newMux()
}
