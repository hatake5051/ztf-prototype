package openid

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"path"
)

/// OP は OpenID Provider の 設定を表す
type OP struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint"`
	EndSessionEndpoint                         string   `json:"end_session_endpoint"`
	JwksURI                                    string   `json:"jwks_uri"`
	CheckSessionIframe                         string   `json:"check_session_iframe"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	IDTokenEncryptionAlgValuesSupported        []string `json:"id_token_encryption_alg_values_supported"`
	IDTokenEncryptionEncValuesSupported        []string `json:"id_token_encryption_enc_values_supported"`
	UserinfoSigningAlgValuesSupported          []string `json:"userinfo_signing_alg_values_supported"`
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	RegistrationEndpoint                       string   `json:"registration_endpoint"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	ClaimsSupported                            []string `json:"claims_supported"`
	ClaimTypesSupported                        []string `json:"claim_types_supported"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported               bool     `json:"request_uri_parameter_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	TLSClientCertificateBoundAccessTokens      bool     `json:"tls_client_certificate_bound_access_tokens"`
}

/// NewOPFetched は issuer から OP の設定情報を取得する。
func NewOPFetched(issuer string) (*OP, error) {
	url, err := url.Parse(issuer)
	if err != nil {
		return nil, err
	}
	url.Path = path.Join(url.Path, "/.well-known/openid-configuration")
	resp, err := http.Get(url.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	if contentType != "application/json" {
		return nil, fmt.Errorf("contentType unmached expected application/json but %s", contentType)
	}
	op := new(OP)
	if err := json.NewDecoder(resp.Body).Decode(op); err != nil {
		return nil, err
	}
	if op.Issuer != issuer {
		return nil, fmt.Errorf("caep: issuer did not match the issuer returned by provider, expected %q got %q", issuer, op.Issuer)
	}
	return op, nil
}
