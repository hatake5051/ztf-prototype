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
	Openid *openid.Conf `json:"openid"`
}
