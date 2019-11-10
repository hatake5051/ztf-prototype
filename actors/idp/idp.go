package idp

import (
	"net/http"
	"soturon/authorizer"
	"soturon/client"
)

type IDP interface {
	Authenticate(w http.ResponseWriter, r *http.Request)
	LoginAndApprove(w http.ResponseWriter, r *http.Request)
	IssueIDToken(w http.ResponseWriter, r *http.Request)
	UserInfo(w http.ResponseWriter, r *http.Request)
}

func New(registration map[string]*client.Config) IDP {
	return idp{Authenticator: authorizer.NewAuthenticator(registration)}
}

type idp struct {
	authorizer.Authenticator
}
