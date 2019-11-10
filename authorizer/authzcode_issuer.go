package authorizer

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"soturon/client"
	"soturon/session"
	"soturon/util"
	"strings"
)

// AuthzCodeIssuer は Oauth2.0 Client の要求をユーザが同意した時に code を発行する
type AuthzCodeIssuer interface {
	// Consent は Oauth2.0 Client の要求を理解し、ユーザに同意を求めるために必要な情報(ClientID と Scopes)を提供する
	// また IssueCode にてリクエストの検証をするためにクッキーで状態管理を行う
	Consent(user *User, w http.ResponseWriter, r *http.Request) (*client.Config, error)
	// IssueCode は ユーザの同意があれば code を OAuth2.0 Client に発行する
	IssueCode(w http.ResponseWriter, r *http.Request) (string, *TokenOptions)
}

// NewAuthzCodeIssuer は AuthzCodeIssuer を生成する
func NewAuthzCodeIssuer(registered ClientRegistration) AuthzCodeIssuer {
	return &authzCodeIssuer{
		registered: registered,
		sessions: &authzSessionManager{
			Manager:    session.NewManager(),
			cookieName: "authorization-server-session-id-when-consent",
		},
	}
}

type authzCodeIssuer struct {
	registered ClientRegistration
	sessions   *authzSessionManager
}

func (a *authzCodeIssuer) Consent(user *User, w http.ResponseWriter, r *http.Request) (*client.Config, error) {
	c, err := a.verifyClient(r)
	if err != nil {
		return nil, err
	}
	param, ok := newReqCodeParam(r)
	if !ok {
		return nil, errors.New("invalid parameter")
	}
	sessionID := a.sessions.UniqueID()
	a.sessions.SetReqCodeParam(sessionID, param)
	a.sessions.Set(sessionID, "user", user)
	req := &client.Config{
		ClientID: c.ClientID,
		Scopes:   param.scopes,
	}
	a.sessions.SetClientConfig(sessionID, req)
	http.SetCookie(w, &http.Cookie{Name: a.sessions.cookieName, Value: sessionID})
	return req, nil
}

func (a *authzCodeIssuer) IssueCode(w http.ResponseWriter, r *http.Request) (string, *TokenOptions) {
	if r.FormValue("approve") != "Approve" {
		return "", nil
	}
	cookie, err := r.Cookie(a.sessions.cookieName)
	if err != nil {
		return "", nil
	}
	sessionID := cookie.Value
	param, ok := a.sessions.extractReqCodeParam(sessionID)
	if !ok {
		return "", nil
	}
	if param.responseType != "code" {
		return "", nil
	}
	c, ok := a.sessions.ExtractClientConfig(sessionID)
	if !ok {
		return "", nil
	}
	var apperovedScopes []string
	for _, s := range param.scopes {
		if sc := r.FormValue("scope_" + s); sc == "on" {
			apperovedScopes = append(apperovedScopes, s)
		}
	}
	var user *User
	if username := r.FormValue("username"); username != "" {
		user = &User{Name: username}
	}
	if i, ok := a.sessions.FindValue(sessionID, "user"); ok {
		if u, ok := i.(*User); ok && u != nil {
			user = u
		}
	}

	opts := &TokenOptions{
		ClientID: c.ClientID,
		Scopes:   apperovedScopes,
		User:     user,
	}

	code := util.RandString(8)
	param.redirectURI.RawQuery = url.Values{"code": {code}, "state": {param.state}}.Encode()
	http.Redirect(w, r, param.redirectURI.String(), http.StatusFound)
	return code, opts
}

// verifyClient は リクエストを検証し、正しければそのリクエストを発行した Client 情報を返す
func (a *authzCodeIssuer) verifyClient(r *http.Request) (*client.Config, error) {
	client, ok := a.registered.Find(r.FormValue("client_id"))
	if !ok {
		return nil, fmt.Errorf("nothing client[%v]", r.FormValue("client_id"))
	}
	if client.RedirectURL != r.FormValue("redirect_uri") {
		return nil, fmt.Errorf("redirect no match %v %v", client.RedirectURL, r.FormValue("redirect_uri"))
	}
	return client, nil
}

type reqCodeParam struct {
	responseType string
	clientID     string
	redirectURI  *url.URL
	state        string
	scopes       []string
}

// newReqCodeParam は callback時に必要となるデータの一式をリクエストから抽出する
func newReqCodeParam(r *http.Request) (*reqCodeParam, bool) {
	rawURL, err := url.PathUnescape(r.FormValue("redirect_uri"))
	if err != nil {
		return nil, false

	}
	rURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, false
	}
	return &reqCodeParam{
		responseType: r.FormValue("response_type"),
		redirectURI:  rURL,
		state:        r.FormValue("state"),
		scopes:       strings.Split(r.FormValue("scope"), " "),
	}, true
}

type authzSessionManager struct {
	session.Manager
	cookieName string
}

func (a *authzSessionManager) SetReqCodeParam(sID string, r *reqCodeParam) bool {
	return a.Manager.Set(sID, "reqCodeParam", r)
}

func (a *authzSessionManager) extractReqCodeParam(sID string) (*reqCodeParam, bool) {
	session, ok := a.Manager.Find(sID)
	if !ok {
		return nil, false
	}
	v, ok := session.Find("reqCodeParam")
	if !ok {
		return nil, false
	}
	r, ok := v.(*reqCodeParam)
	return r, ok
}

func (a *authzSessionManager) SetClientConfig(sID string, v *client.Config) bool {
	return a.Manager.Set(sID, "clientConfig", v)
}

func (a *authzSessionManager) ExtractClientConfig(sID string) (*client.Config, bool) {
	session, ok := a.Manager.Find(sID)
	if !ok {
		return nil, false
	}
	v, ok := session.Find("clientConfig")
	if !ok {
		return nil, false
	}
	c, ok := v.(*client.Config)
	return c, ok
}
