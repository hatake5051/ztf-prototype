package pip

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/hatake5051/ztf-prototype/ac"
	ztfopenid "github.com/hatake5051/ztf-prototype/openid"
	"github.com/lestrrat-go/jwx/jwt/openid"
)

// SubPIPConf は subPIP の設定情報
type SubPIPConf map[string]*ztfopenid.Conf

func (conf *SubPIPConf) new(sm SessionStoreForSPIP) *sPIP {
	sPIP := &sPIP{session: sm}
	for idp, rpconf := range *conf {
		rp := rpconf.New()
		sPIP.agents.Store(idp, &authnagent{rp, sm.SetIDToken})
	}
	return sPIP
}

type sPIP struct {
	session SessionStoreForSPIP
	agents  sync.Map
}

type SessionStoreForSPIP interface {
	Identify(session string) (ac.Subject, error)
	SetIDToken(session string, idtoken openid.Token) error
}

func (pip *sPIP) Subject(session string) (ac.Subject, error) {
	sub, err := pip.session.Identify(session)
	if err != nil {
		return nil, newE(err, SubjectUnAuthenticated)
	}
	return sub, nil
}

func (pip *sPIP) SubjectAuthNAgent(idp string) (AuthNAgent, error) {
	v, ok := pip.agents.Load(idp)
	if !ok {
		return nil, fmt.Errorf("この IdP(%s) は使えないよ", idp)
	}
	return v.(*authnagent), nil
}

// ac.AuthNAgent を実装する
type authnagent struct {
	ztfopenid.RP
	setSubject func(session string, idtoken openid.Token) error
}

// Callback は OIDC フローでコールバックし IDToken を取得するとそれを PIP に保存する
func (a *authnagent) Callback(session string, r *http.Request) error {
	idtoken, err := a.RP.CallbackAndExchange(r)
	if err != nil {
		return err
	}
	return a.setSubject(session, idtoken)
}
