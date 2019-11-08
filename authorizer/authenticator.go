package authorizer

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"soturon/client"
)

type Authenticator interface {
	Authenticate(w http.ResponseWriter, r *http.Request)
	LoginAndApprove(w http.ResponseWriter, r *http.Request)
	IssueIDToken(w http.ResponseWriter, r *http.Request)
}

func NewAuthenticator(registration map[string]*client.Config) Authenticator {
	registered := NewClientRegistration(registration)
	return &authenticator{
		front:  NewAuthzCodeIssuer(registered),
		back:   NewIDTokenIssuer(registered),
		tokens: NewIDTokenStore(),
	}
}

type authenticator struct {
	front  AuthzCodeIssuer
	back   IDTokenIssuer
	tokens IDTokenStore
}

func (a *authenticator) Authenticate(w http.ResponseWriter, r *http.Request) {
	c, err := a.front.Consent(w, r)
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "%v", err)
		return
	}
	fmt.Fprint(w, authenticatePage(c))
	return
}

func (a *authenticator) LoginAndApprove(w http.ResponseWriter, r *http.Request) {
	code, approved := a.front.IssueCode(w, r)
	if code != "" {
		fmt.Fprintf(w, "Access Denied")
	}
	a.back.AddCode(code, approved)
}

type loginInfo struct {
}

func (a *authenticator) IssueIDToken(w http.ResponseWriter, r *http.Request) {
	t, ok := a.back.IDToken(r)
	if !ok {
		w.WriteHeader(400)
		fmt.Fprintf(w, "cannot return token")
		return
	}
	tJSON, err := json.Marshal(t)
	if err != nil {
		w.WriteHeader(500)
		fmt.Fprintf(w, "cannot marshal token to JSON")
		return
	}
	log.Printf("idp issue token %#v", t)
	a.tokens.Add(t)
	w.Header().Set("Content-Type", "application/json")
	w.Write(tJSON)
}

func authenticatePage(c *client.Config) string {
	reqScope := "<ul>"
	for _, s := range c.Scopes {
		reqScope += fmt.Sprintf(`<li>
		<input type="checkbox" name="scope_%v" checked="checked">
		%v</li>
		`, s, s)
	}
	reqScope += "</ul>"
	return fmt.Sprintf(`
	<html><head/><body>
	%v が以下の権限を要求しています。<br>
	承認する権限にチェックを入れ、ログインをしてください
	<form  action="/approve" method="POST">
		お名前: <input type="text" name="username">
		%s
		<input type="submit" name="approve" value="Approve">
		<input type="submit" name="deny" value="Deny">
	</form></body></html>`, c.ClientID, reqScope)
}
