package cap

import (
	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/openid"
	"github.com/hatake5051/ztf-prototype/uma"
)

// Conf は CAP の設定情報
type Conf struct {
	CAP  *CAPConf  `json:"cap"`
	UMA  *UMAConf  `json:"uma"`
	CAEP *CAEPConf `json:"caep"`
}

// CAPConf は CAP その者の設定情報
type CAPConf struct {
	Contexts map[string][]string `json:"contexts"`
	Openid   *Openid             `json:"openid"`
}

// UMAConf は CAP で UMA ResSrv として振る舞うための設定情報
type UMAConf struct {
	AuthZ        string `json:"authZ"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func (c *UMAConf) to() *uma.ResSrvConf {
	return &uma.ResSrvConf{
		AuthZSrv: c.AuthZ,
		ClientCred: struct {
			ID     string
			Secret string
		}{c.ClientID, c.ClientSecret},
	}
}

// Metadata は CAP で CAEP Transmitter として振る舞うためのメタデータ
type Metadata struct {
	Issuer                   string   `json:"issuer"`
	JwksURI                  string   `json:"jwks_uri"`
	SupportedVersions        []string `json:"supported_versions"`
	DeliveryMethodsSupported []string `json:"delivery_methods_supported"`
	StatusEndpoint           string   `json:"status_endpoint"`
	ConfigurationEndpoint    string   `json:"configuration_endpoint"`
	AddSubjectEndpoint       string   `json:"add_subject_endpoint"`
	RemoveSubjectEndpoint    string   `json:"remove_subject_endpoint"`
	VerificationEndpoint     string   `json:"verification_endpoint"`
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

// CAEPConf は CAP で CAEP Transmitter として振る舞うための設定情報
type CAEPConf struct {
	Metadata  Metadata `json:"metadata"`
	Openid    Openid   `json:"openid"`
	Receivers map[string]struct {
		ClientID string `json:"client_id"`
		Host     string `json:"host"`
	} `json:"receivers"`
}

func (c *CAEPConf) to() *caep.TransConf {
	return &caep.TransConf{
		Tr: &caep.Transmitter{
			Issuer:                   c.Metadata.Issuer,
			JwksURI:                  c.Metadata.JwksURI,
			SupportedVersions:        c.Metadata.SupportedVersions,
			DeliveryMethodsSupported: c.Metadata.DeliveryMethodsSupported,
			ConfigurationEndpoint:    c.Metadata.ConfigurationEndpoint,
			StatusEndpoint:           c.Metadata.StatusEndpoint,
			AddSubjectEndpoint:       c.Metadata.AddSubjectEndpoint,
			RemoveSubjectEndpoint:    c.Metadata.RemoveSubjectEndpoint,
			VerificationEndpoint:     c.Metadata.VerificationEndpoint,
		},
	}
}
