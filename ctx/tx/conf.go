package tx

import (
	"net/url"

	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/uma"
)

// Conf は CAP の設定情報
type Conf struct {
	Contexts map[string][]string `json:"contexts"`
	UMA      *UMAConf            `json:"uma"`
	CAEP     *CAEPConf           `json:"caep"`
}

// UMAConf は CAP で UMA ResSrv として振る舞うための設定情報
type UMAConf struct {
	AuthZ        string `json:"authZ"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURL  string `json:"redirect_url"`
}

func (c *UMAConf) to() *uma.ResSrvConf {
	ur, err := url.Parse(c.AuthZ)
	if err != nil {
		panic("UMAConf.AuthZ が URL でない")
	}
	return &uma.ResSrvConf{
		AuthZSrv: ur,
		PATClient: struct {
			ID          string
			Secret      string
			RedirectURL string
		}{c.ClientID, c.ClientSecret, c.RedirectURL},
	}
}

// CAEPConf は CAP で CAEP Transmitter として振る舞うための設定情報
type CAEPConf struct {
	Metadata  *caep.TransmitterConf `json:"metadata"`
	Receivers map[string]struct {
		ClientID string `json:"client_id"`
		Host     string `json:"host"`
	} `json:"receivers"`
}

func (c *CAEPConf) to() *caep.TxConf {
	return &caep.TxConf{
		Tr: c.Metadata,
	}
}
