package tx

import (
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
	JwksURI      string `json:"jwks_uri"`
}

func (c *UMAConf) to() *uma.ResSrvConf {
	return &uma.ResSrvConf{
		AuthZSrv: c.AuthZ,
		PATClient: struct {
			ID          string
			Secret      string
			RedirectURL string
		}{c.ClientID, c.ClientSecret, c.RedirectURL},
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

// CAEPConf は CAP で CAEP Transmitter として振る舞うための設定情報
type CAEPConf struct {
	Metadata  Metadata `json:"metadata"`
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
