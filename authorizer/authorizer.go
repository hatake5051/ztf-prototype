package authorizer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"soturon/client"

	jwt "github.com/dgrijalva/jwt-go"
)

type Authorizer interface {
	Authorize(http.ResponseWriter, *http.Request)
	Approve(w http.ResponseWriter, r *http.Request)
	IssueToken(w http.ResponseWriter, r *http.Request)
	IntroSpect(w http.ResponseWriter, r *http.Request)
}

func New(registration map[string]*client.Config) Authorizer {
	registered := NewClientRegistration(registration)
	return &authorizer{
		front:  NewAuthzCodeIssuer(registered),
		back:   NewTokenIssuer(registered),
		tokens: NewTokenStore(),
	}
}

type authorizer struct {
	front  AuthzCodeIssuer
	back   TokenIssuer
	tokens TokenStore
}

func (a *authorizer) Authorize(w http.ResponseWriter, r *http.Request) {
	rctx := client.NewRContext(r.Context())
	idtoken, ok := rctx.IDToken()
	if !ok {
		w.WriteHeader(400)
		fmt.Fprintf(w, "must authenticate")
		return
	}
	c, err := a.front.Consent(w, r)
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "%v", err)
		return
	}
	fmt.Fprint(w, consentPage(c, idtoken))
	return
}

func (a *authorizer) Approve(w http.ResponseWriter, r *http.Request) {
	code, c := a.front.IssueCode(w, r)
	a.back.AddCode(code, c)
}

func (a *authorizer) IssueToken(w http.ResponseWriter, r *http.Request) {
	t, ok := a.back.Token(r)
	if !ok {
		w.WriteHeader(400)
		fmt.Fprintf(w, "cannoe return token")
		return
	}
	tJSON, err := json.Marshal(t)
	if err != nil {
		w.WriteHeader(500)
		fmt.Fprintf(w, "cannot marshal token to JSON")
		return
	}
	a.tokens.Add(t)
	w.Header().Set("Content-Type", "application/json")
	w.Write(tJSON)
}

func (a *authorizer) IntroSpect(w http.ResponseWriter, r *http.Request) {
	t, err := a.tokens.Find(r.FormValue("token"))
	if err != nil {
		w.WriteHeader(404)
		fmt.Fprintf(w, "introspect %v", err)
		return
	}
	fmt.Fprintf(w, "Correct! %#v", t)
}

func consentPage(c *client.Config, idtoken *jwt.Token) string {
	claims, ok := idtoken.Claims.(jwt.MapClaims)
	if !ok {
		return "errorrrrr"
	}
	hello := fmt.Sprintf("%v さんこんにちは。<Br> id-token: %#v", claims["sub"], claims)

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
	%v<br>
	%v が以下の権限を要求しています
	<form  action="/approve" method="POST">
		%s
		<input type="submit" name="approve" value="Approve">
		<input type="submit" name="deny" value="Deny">
	</form></body></html>`, hello, c.ClientID, reqScope)
}
