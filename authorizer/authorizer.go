package authorizer

import (
	"encoding/json"
	"net/http"
	"soturon/client"
)

type Authorizer interface {
	// Authorize は Oauth2.0 Client の要求を理解し、ユーザに同意を求めるために必要な情報(ClientID と Scopes)を提供する。
	// このメソッドを使う場合、返り値を元にユーザに同意をもとめるviewを用意しなければならない。
	Authorize(*User, http.ResponseWriter, *http.Request) (*client.Config, error)
	// Approve は ユーザの同意があれば code を発行し、それを OAuth2.0 Client callback endpoint へリダイレクトする。
	Approve(w http.ResponseWriter, r *http.Request)
	// IssueToken は client から code を受け取り、検証が成功すればトークンを発行およびJSonエンコードしてレスポンスする。
	IssueToken(w http.ResponseWriter, r *http.Request)
	// IntroSpect は リクエストパラメータのトークンが有効か判定し、トークンに関する追加情報を返す
	IntroSpect(w http.ResponseWriter, r *http.Request)
}

func New(registration map[string]*client.Config, issueURL string) Authorizer {
	registered := NewClientRegistration(registration)
	return &authorizer{
		front:    NewAuthzCodeIssuer(registered),
		back:     NewTokenIssuer(registered),
		tokens:   NewTokenStore(),
		issueURL: issueURL,
	}
}

type authorizer struct {
	front    AuthzCodeIssuer
	back     TokenIssuer
	tokens   TokenStore
	issueURL string
}

func (a *authorizer) Authorize(user *User, w http.ResponseWriter, r *http.Request) (*client.Config, error) {
	return a.front.Consent(user, w, r)
}

func (a *authorizer) Approve(w http.ResponseWriter, r *http.Request) {
	code, c := a.front.IssueCode(w, r)
	a.back.AddCode(code, c)
}

func (a *authorizer) IssueToken(w http.ResponseWriter, r *http.Request) {
	t, opts, ok := a.back.Token(r)
	if !ok {
		w.WriteHeader(400)
		return
	}
	tJSON, err := json.Marshal(t)
	if err != nil {
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(tJSON)
	a.tokens.Add(t, opts)
	return
}

type IntroToken struct {
	Active   bool   `json:"active"`
	UserName string `json:"username"`
	Scope    string `json:"scope"`
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
}

func (a *authorizer) IntroSpect(w http.ResponseWriter, r *http.Request) {
	t, ops, err := a.tokens.Find(r.FormValue("token"))
	if err != nil {
		w.WriteHeader(404)
		return
	}
	it := &IntroToken{
		Active:   true,
		UserName: ops.User.Name,
		Scope:    t.Scope,
		Issuer:   a.issueURL,
		Audience: "http://" + r.Host,
	}
	itJSON, err := json.Marshal(it)
	if err != nil {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(itJSON)
}
