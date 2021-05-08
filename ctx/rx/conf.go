package rx

import (
	"github.com/hatake5051/ztf-prototype/caep"
	"golang.org/x/oauth2/clientcredentials"
)

type Conf struct {
	Contexts map[string][]string `json:"contexts"`
	UMA      UMAConf             `json:"uma"`
	CAEP     CAEPConf            `json:"caep"`
}

type UMAConf struct {
	ReqPartyCredential struct {
		Iss      string `json:"iss"`
		Name     string `json:"name"`
		Password string `json:"password"`
	} `json:"req_party_credential"`
	ClientCredential struct {
		AuthZ    string `json:"authZ"`
		TokenURL string `json:"token_url"`
		ID       string `json:"id"`
		Secret   string `json:"secret"`
	} `json:"client_credential"`
}

func (conf *UMAConf) to() *clientcredentials.Config {
	return &clientcredentials.Config{
		ClientID:     conf.ClientCredential.ID,
		ClientSecret: conf.ClientCredential.Secret,
		TokenURL:     conf.ClientCredential.TokenURL,
	}
}

type CAEPConf struct {
	// host は Receiver のホスト名
	Host string `json:"host"`
	// RecvCtxEndpoint は Ctx を受け取るエンドポイント
	Endpoint string `json:"pushed_endpoint"`
	// Issuer は Transmitter のホスト名
	Iss string `json:"iss"`
}

func (conf *CAEPConf) to() *caep.RecvConf {
	return &caep.RecvConf{
		Host:         conf.Host,
		RecvEndpoint: conf.Endpoint,
		Issuer:       conf.Iss,
	}
}
