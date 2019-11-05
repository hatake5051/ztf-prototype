package infra

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

type authzServer struct {
	authzEndpoint *url.URL
	tokenEndpoint *url.URL
}

type clientConfig struct {
	clientID     string
	clientSecret string
	redirectURL  string
}

type pef struct {
	authzServer  authzServer
	clientConfig clientConfig
	state        string
	accessToken  string
	scope        []string
}

func (p *pef) index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`
	<html><head/><body>
		<a href="http://localhost:9000/authorize">authorize</a>
	</body></html>
	`))
}

func (p *pef) redirectToAuthorizer(w http.ResponseWriter, r *http.Request) {
	p.accessToken = ""
	p.state = "RANDOM_STRING"
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {p.clientConfig.clientID},
		"redirect_uri":  {p.clientConfig.redirectURL},
		"state":         {p.state},
	}
	authorizeURL := url.URL{
		Scheme:   "http",
		Host:     p.authzServer.authzEndpoint.Host,
		Path:     p.authzServer.authzEndpoint.Path,
		RawQuery: v.Encode(),
	}
	http.Redirect(w, r, authorizeURL.String(), http.StatusFound)
}

type token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

func (p *pef) exchangeCodeForToken(w http.ResponseWriter, r *http.Request) {
	if e := r.FormValue("error"); e != "" {
		fmt.Fprintf(w, "%v", e)
		return
	}
	if p.state != r.FormValue("state") {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "state is not match; expect: %v, but: %v", p.state, r.FormValue("state"))
		return
	}
	code := r.FormValue("code")
	if code == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "code is empty")
		return
	}
	v := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {p.clientConfig.redirectURL},
	}
	req, err := http.NewRequest("POST", p.authzServer.tokenEndpoint.String(), strings.NewReader(v.Encode()))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "server internal error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(p.clientConfig.clientID), url.QueryEscape(p.clientConfig.clientSecret))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "request to tokenEndpoint error: %v", err)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "error: %v", err)
		return
	}
	if status := resp.StatusCode; status < 200 || status >= 300 {
		w.WriteHeader(status)
		fmt.Fprintf(w, "error: %v", status)
		return
	}
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "mime.parsemedia error: %v", err)
		return
	}
	if contentType != "application/json" {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "not supported content-type: %v", contentType)
		return
	}
	var t = &token{}
	if err = json.Unmarshal(body, t); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "json parse failed %v", body)
		return
	}

	fmt.Fprintf(w, "Authorization: %v %v", t.TokenType, t.AccessToken)
	return

}

func (p *pef) newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", p.index)
	mux.HandleFunc("/authorize", p.redirectToAuthorizer)
	mux.HandleFunc("/callback", p.exchangeCodeForToken)
	return mux
}

func NewPEF() *http.ServeMux {
	authURL, _ := url.Parse("http://localhost:9001/authorize")
	tokenURL, _ := url.Parse("http://localhost:9001/token")
	pef := &pef{
		authzServer: authzServer{
			authzEndpoint: authURL,
			tokenEndpoint: tokenURL,
		},
		clientConfig: clientConfig{
			clientID:     "oauth-client-1",
			clientSecret: "oauth-client-secret-1",
			redirectURL:  "http://localhost:9000/callback",
		},
	}
	return pef.newMux()
}
