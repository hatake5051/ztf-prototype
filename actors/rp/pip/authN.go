package pip

import (
	"net/http"

	ztfopenid "github.com/hatake5051/ztf-prototype/openid"
	"github.com/lestrrat-go/jwx/jwt/openid"
)

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
