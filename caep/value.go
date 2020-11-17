package caep

import (
	"encoding/json"
	"fmt"
	"log"
	"mime"
	"net/http"
	"net/url"
)

// Transmitter は caep Transmitter の設定情報を表す
type Transmitter struct {
	Issuer                string
	ConfigurationEndpoint string
	StatusEndpoint        string
	AddSubjectEndpoint    string
}

type transmitterJSON struct {
	Issuer                   string   `json:"issuer"`
	JwksURI                  string   `json:"jwks_uri"`
	DeliveryMethodsSupported []string `json:"delivery_methods_supported"`
	ConfigurationEndpoint    string   `json:"configuration_endpoint"`
	StatusEndpoint           string   `json:"status_endpoint"`
	AddSubjectEndpoint       string   `json:"add_subject_endpoint"`
	RemoveSubjectEndpoint    string   `json:"remove_subject_endpoint"`
	VerificationEndpoint     string   `json:"verification_endpoint"`
}

func NewTransmitter(issuer string) (*Transmitter, error) {
	url, err := url.Parse(issuer)
	if err != nil {
		log.Printf("CAEP Transmitter の issuer url parse に失敗: %v\n", err)
		return nil, err
	}
	if url.Path == "" {
		url.Path = "/.well-known/sse-configuration" + "/"
	} else {
		url.Path = "/.well-known/sse-configuration" + url.Path
	}
	resp, err := http.Get(url.String())
	if err != nil {
		return nil, err
	}
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
	defer resp.Body.Close()
	t := new(transmitterJSON)
	if err := json.NewDecoder(resp.Body).Decode(t); err != nil {
		return nil, err
	}

	if t.Issuer != issuer {
		return nil, fmt.Errorf("caep: issuer did not match the issuer returned by provider, expected %q got %q", issuer, t.Issuer)
	}
	return &Transmitter{t.Issuer, t.ConfigurationEndpoint, t.StatusEndpoint, t.AddSubjectEndpoint}, nil
}

// CtxStreamStatus は caep.EventStreamStatus を表す
type CtxStreamStatus struct {
	Status string `json:"status"`
	SpagID string `json:"spag_id"`
}

// CtxStreamConfig は caep.EventStreamConfiguration を表す
type CtxStreamConfig struct {
	Iss      string   `json:"iss"`
	Aud      []string `json:"aud"`
	Delivery struct {
		DeliveryMethod string `json:"delivery_method"`
		URL            string `json:"url"`
	} `json:"delivery"`
	EventsSupported []string `json:"events_supported"`
	EventsRequested []string `json:"events_requested"`
	EventsDelivered []string `json:"events_delivered"`
}

type AddSubReq struct {
	Sub struct {
		SubType string `json:"subject_type"`
		SpagID  string `json:"spag_id"`
	} `json:"subject"`
	ReqCtx map[string][]string `json:"events_scopes_requested"`
}

// Context は caep.Event を拡張したものでコンテキストを表す
type Context struct {
	Issuer      string
	ID          string
	Scopes      []string
	ScopeValues map[string]string
}

// SET は caep で送受信される Security Event Token の Claim 部分を表す
type SETClaim struct {
	Jti    string                `json:"jti"`
	Iss    string                `json:"iss"`
	Aud    []string              `json:"aud"`
	Iat    string                `json:"iat"`
	Events map[string]EventClaim `json:"events"`
}

func (set *SETClaim) Valid() error {
	return nil
}

func (set *SETClaim) ToSubAndCtx() (spagID string, c *Context) {
	for id, eClaim := range set.Events {
		return eClaim.Subject.SpagID, &Context{
			Issuer:      set.Iss,
			ID:          id,
			ScopeValues: eClaim.Property,
		}
	}
	return "", nil
}

type EventClaim struct {
	ID      string `json:"-"`
	Subject struct {
		SubType string `json:"subject_type"`
		SpagID  string `json:"spag_id"`
	} `json:"subject"`
	Property map[string]string `json:"property"`
}

func NewSETEventsClaim(spagID string, c *Context) map[string]EventClaim {
	eClaim := EventClaim{
		ID: c.ID,
		Subject: struct {
			SubType string "json:\"subject_type\""
			SpagID  string "json:\"spag_id\""
		}{"spag", spagID},
		Property: c.ScopeValues,
	}
	return map[string]EventClaim{
		eClaim.ID: eClaim,
	}
}
