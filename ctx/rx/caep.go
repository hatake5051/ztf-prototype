package rx

import (
	"context"
	"net/http"

	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/ctx"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

func (conf *CAEPConf) new(cliConf *clientcredentials.Config, u *umaClient, newSub func(*caep.EventSubject) ctx.Sub) (caep.Rx, error) {
	// sse stream アクセスようのトークンを取得する
	t, err := cliConf.Token(context.Background())
	if err != nil {
		return nil, err
	}
	a := &setAuthHeaders{u, t, newSub}
	return conf.to().New(a), nil

}

type setAuthHeaders struct {
	uma    *umaClient
	t      *oauth2.Token
	newSub func(*caep.EventSubject) ctx.Sub
}

func (s *setAuthHeaders) ForConfig(r *http.Request) {
	s.t.SetAuthHeader(r)
}

func (s *setAuthHeaders) ForSubAdd(sub *caep.EventSubject, r *http.Request) {
	rpt, err := s.uma.RPT(s.newSub(sub))
	if err != nil {
		return
	}
	rpt.SetAuthHeader(r)
}
