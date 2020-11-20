package rp

import (
	"github.com/hatake5051/ztf-prototype/ac"
	"github.com/hatake5051/ztf-prototype/ac/controller"
	"github.com/hatake5051/ztf-prototype/ac/pdp"
	"github.com/hatake5051/ztf-prototype/actors/rp/pip"
	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/openid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type Conf struct {
	PIP PIP `json:"pip"`
	PDP PDP `json:"pdp"`
}

func (conf *Conf) New(repo ac.Repository) ac.Controller {
	pip, err := conf.PIP.To().New(repo)
	if err != nil {
		panic(err)
	}
	pdp, err := conf.PDP.To().New()
	if err != nil {
		panic(err)
	}
	return controller.New(pip, pdp)

}

type PDP struct {
}

func (c *PDP) To() *pdp.Conf {
	return &pdp.Conf{}
}

type PIP struct {
	*SubPIP `json:"sub"`
	*CtxPIP `json:"ctx"`
}

func (c *PIP) To() *pip.Conf {
	return &pip.Conf{
		SubPIPConf: c.SubPIP.to(),
		CtxPIPConf: c.CtxPIP.to(),
	}
}

type SubPIP struct {
	// IssuerList は認証サーバとして利用可能な OP のリスト
	IssList []string `json:"iss_list"`
	// RPConfMap は Issuer ごとの RP 設定情報
	RPConfig map[string]*OIDCRP `json:"rp_config"`
}

func (c *SubPIP) to() *pip.SubPIPConf {
	tmp := make(map[string]*openid.Conf)
	for k, v := range c.RPConfig {
		tmp[k] = v.to()
	}
	return &pip.SubPIPConf{
		IssuerList: c.IssList,
		RPConf:     tmp,
	}
}

type OIDCRP struct {
	Iss          string `json:"iss"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURL  string `json:"redirect_url"`
}

func (c *OIDCRP) to() *openid.Conf {
	return &openid.Conf{
		Issuer:       c.Iss,
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.RedirectURL,
	}
}

// CtxPIPConf は ctxPIP の設定情報
type CtxPIP struct {
	// CtxID2CAP はコンテキストID -> そのコンテキストを管理するCAP名
	CtxToCAP map[string]string `json:"ctx_to_cap"`
	// Cap2RPConf は CAP 名 -> その CAP に対する RP 設定情報
	CAPToRP map[string]*CAPRP `json:"cap_to_rp"`
}

func (c *CtxPIP) to() *pip.CtxPIPConf {
	tmp := make(map[string]*pip.CAPRPConf)
	for k, v := range c.CAPToRP {
		tmp[k] = v.to()
	}
	return &pip.CtxPIPConf{
		CtxID2CAP: c.CtxToCAP,
		CAP2RP:    tmp,
	}
}

type CAPRP struct {
	AuthN *AuthNForCAEPRecv `json:"authN"`
	Recv  *Recv             `json:"recv"`
}

func (c *CAPRP) to() *pip.CAPRPConf {
	return &pip.CAPRPConf{
		AuthN: c.AuthN.to(),
		Recv:  c.Recv.to(),
	}
}

// AuthNForCAEPRecvConf は CAEP の Receriver でサブジェクト認証を管理するための設定情報
type AuthNForCAEPRecv struct {
	CAPName string  `json:"cap"`
	OIDCRP  *OIDCRP `json:"rp_config"`
}

func (c *AuthNForCAEPRecv) to() *pip.AuthNForCAEPRecvConf {
	return &pip.AuthNForCAEPRecvConf{
		CAPName: c.CAPName,
		OIDCRP:  c.OIDCRP.to(),
	}
}

// CAEPRecvConf は CAEP の Receiver となるための設定情報
type Recv struct {
	CAEPRecv *CAEPRecv `json:"caep"`
	// Oauth2Conf は stream config/status endpoit の保護に使う
	Oauth2Conf *Oauth2ClientCred `json:"oauth2"`
	// UMAConf は sub add endpoint の保護に使う
	UMAConf *UMAClient `json:"uma"`
}

func (c *Recv) to() *pip.CAEPRecvConf {
	return &pip.CAEPRecvConf{
		CAEPRecv:   c.CAEPRecv.to(),
		Oauth2Conf: c.Oauth2Conf.to(),
		UMAConf:    c.UMAConf.to(),
	}
}

// CAEPRecvConf は caep の Receiver の設定情報を表す
type CAEPRecv struct {
	// host は Receiver のホスト名
	Host string `json:"host"`
	// RecvCtxEndpoint は Ctx を受け取るエンドポイント
	Endpoint string `json:"pushed_endpoint"`
	// Issuer は Transmitter のホスト名
	Iss string `json:"iss"`
}

func (c *CAEPRecv) to() *caep.RecvConf {
	return &caep.RecvConf{
		Host:         c.Host,
		RecvEndpoint: c.Endpoint,
		Issuer:       c.Iss,
	}
}

type Oauth2ClientCred struct {
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	TokenEndpoint string `json:"token_endpoint"`
}

func (c *Oauth2ClientCred) to() *clientcredentials.Config {
	return &clientcredentials.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		TokenURL:     c.TokenEndpoint,
	}
}

// UMAClientConf は CAP で UMAClint となるための設定情報
type UMAClient struct {
	ReqPartyCredential struct {
		Iss      string `json:"iss"`
		Name     string `json:"name"`
		Password string `json:"password"`
	} `json:"req_party_credential"`
	ClientCredential struct {
		AuthZ  string `json:"authZ"`
		ID     string `json:"id"`
		Secret string `json:"secret"`
	} `json:"client_credential"`
}

func (c *UMAClient) to() *pip.UMAClientConf {
	return &pip.UMAClientConf{
		ReqPartyCredential: struct {
			Issuer string
			Name   string
			Pass   string
		}{
			Issuer: c.ReqPartyCredential.Iss,
			Name:   c.ReqPartyCredential.Name,
			Pass:   c.ReqPartyCredential.Password,
		},
		ClientCredential: struct {
			AuthzSrv string
			ID       string
			Secret   string
		}{
			AuthzSrv: c.ClientCredential.AuthZ,
			ID:       c.ClientCredential.ID,
			Secret:   c.ClientCredential.Secret,
		},
	}
}

type Oauth2ResOwnerPass struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Endpoints    struct {
		AuthZ string `json:"authZ"`
		Token string `json:"token"`
	} `json:"endpoints"`
	RedirectURL string `json:"redirect_url"`
}

func (c *Oauth2ResOwnerPass) to() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  c.Endpoints.AuthZ,
			TokenURL: c.Endpoints.Token,
		},
		RedirectURL: c.RedirectURL,
	}
}
