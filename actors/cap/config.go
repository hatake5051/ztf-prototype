package cap

import (
	"github.com/hatake5051/ztf-prototype/ctx/tx"
	"github.com/hatake5051/ztf-prototype/openid"
)

// Conf は CAP の設定情報
type Conf struct {
	CAP *CAPConf `json:"cap"`
	Tx  *tx.Conf `json:"tx"`
}

// CAPConf は CAP その者の設定情報
type CAPConf struct {
	Openid *Openid `json:"openid"`
}

// Openid は CAP で Openid Connect RP として振る舞うための設定情報
type Openid struct {
	Issuer      string `json:"issuer"`
	RpID        string `json:"rp_id"`
	RpSecret    string `json:"rp_secret"`
	RedirectURL string `json:"redirect_url"`
}

func (c *Openid) to() *openid.Conf {
	return &openid.Conf{
		Issuer:       c.Issuer,
		ClientID:     c.RpID,
		ClientSecret: c.RpSecret,
		RedirectURL:  c.RedirectURL,
	}
}
