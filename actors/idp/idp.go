package idp

import (
	"net/http"
	"soturon/authorizer"
	"soturon/client"
)

type Conf struct {
	Addr string
}

func (c *Conf) AuthenticateEndpint() string {
	return "http://" + c.Addr + "/authenticate"
}

func (c *Conf) TokenEndpint() string {
	return "http://" + c.Addr + "/token"
}

func (c *Conf) UserInfoEndpoint() string {
	return "http://" + c.Addr + "/userinfo"
}

type IDP interface {
	Authenticate(w http.ResponseWriter, r *http.Request)
	LoginAndApprove(w http.ResponseWriter, r *http.Request)
	IssueIDToken(w http.ResponseWriter, r *http.Request)
	UserInfo(w http.ResponseWriter, r *http.Request)
}

func New(host string, registration map[string]*client.Config) IDP {
	return idp{Authenticator: authorizer.NewAuthenticator(host, registration)}
}

type idp struct {
	authorizer.Authenticator
}
