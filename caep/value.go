package caep

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"path"
)

// Transmitter は caep Transmitter の設定情報を表す
type Transmitter struct {
	Issuer                   string
	JwksURI                  string
	SupportedVersions        []string
	DeliveryMethodsSupported []string
	ConfigurationEndpoint    string
	StatusEndpoint           string
	AddSubjectEndpoint       string
	RemoveSubjectEndpoint    string
	VerificationEndpoint     string
}

func (t *Transmitter) Write(w io.Writer) error {
	j := &transmitterJSON{
		Issuer:                   t.Issuer,
		JwksURI:                  t.JwksURI,
		SupportedVersions:        t.SupportedVersions,
		DeliveryMethodsSupported: t.DeliveryMethodsSupported,
		ConfigurationEndpoint:    t.ConfigurationEndpoint,
		StatusEndpoint:           t.StatusEndpoint,
		AddSubjectEndpoint:       t.AddSubjectEndpoint,
		RemoveSubjectEndpoint:    t.RemoveSubjectEndpoint,
		VerificationEndpoint:     t.VerificationEndpoint,
	}
	return json.NewEncoder(w).Encode(j)
}

func NewTransmitter(r io.Reader) (*Transmitter, error) {
	t := new(transmitterJSON)
	if err := json.NewDecoder(r).Decode(t); err != nil {
		return nil, err
	}
	tr := &Transmitter{
		Issuer:                   t.Issuer,
		JwksURI:                  t.JwksURI,
		SupportedVersions:        t.SupportedVersions,
		DeliveryMethodsSupported: t.DeliveryMethodsSupported,
		ConfigurationEndpoint:    t.ConfigurationEndpoint,
		StatusEndpoint:           t.StatusEndpoint,
		AddSubjectEndpoint:       t.AddSubjectEndpoint,
		RemoveSubjectEndpoint:    t.RemoveSubjectEndpoint,
		VerificationEndpoint:     t.VerificationEndpoint,
	}
	return tr, nil
}

func NewTransmitterFetced(issuer string) (*Transmitter, error) {
	url, err := url.Parse(issuer)
	if err != nil {
		log.Printf("CAEP Transmitter の issuer url parse に失敗: %v\n", err)
		return nil, err
	}
	url.Path = path.Join("/.well-known/sse-configuration", url.Path)
	fmt.Printf("urlpath sse %v\n", url)
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
	tr, err := NewTransmitter(resp.Body)
	if err != nil {
		return nil, err
	}
	if tr.Issuer != issuer {
		return nil, fmt.Errorf("caep: issuer did not match the issuer returned by provider, expected %q got %q", issuer, tr.Issuer)
	}
	return tr, nil
}

type transmitterJSON struct {
	Issuer                   string   `json:"issuer"`
	JwksURI                  string   `json:"jwks_uri"`
	SupportedVersions        []string `json:"supported_versions"`
	DeliveryMethodsSupported []string `json:"delivery_methods_supported"`
	ConfigurationEndpoint    string   `json:"configuration_endpoint"`
	StatusEndpoint           string   `json:"status_endpoint"`
	AddSubjectEndpoint       string   `json:"add_subject_endpoint"`
	RemoveSubjectEndpoint    string   `json:"remove_subject_endpoint"`
	VerificationEndpoint     string   `json:"verification_endpoint"`
}

// Receiver は　を表す
type Receiver struct {
	// ID は Transmitter における Receiver の識別子
	ID string
	// Host は Receiver のホスト名
	Host string
	// StreamConf は最も最近の Stream COnfig 情報を持つ
	StreamConf *StreamConfig
}

// StreamStatus は caep.EventStreamStatus を表す
type StreamStatus struct {
	Status      string              `json:"status"`
	SpagID      string              `json:"spag_id"`
	EventScopes map[string][]string `json:"events_scopes"`
}

type ReqChangeOfStreamStatus struct {
	StreamStatus
	Authorization string `json:"authorization"`
	Reason        string `json:"reason"`
}

// StreamConfig は caep.EventStreamConfiguration を表す
type StreamConfig struct {
	Iss      string   `json:"iss"`
	Aud      []string `json:"aud"`
	Delivery struct {
		DeliveryMethod string `json:"delivery_method"`
		URL            string `json:"url"`
	} `json:"delivery,omitempty"`
	EventsSupported []string `json:"events_supported"`
	EventsRequested []string `json:"events_requested"`
	EventsDelivered []string `json:"events_delivered"`
}

func (c *StreamConfig) Update(n *StreamConfig) (ismodified bool) {
	if n.Iss != "" && n.Iss != c.Iss {
		c.Iss = n.Iss
	}
	if len(n.Aud) > 0 && len(n.Aud) != len(c.Aud) {
		c.Aud = n.Aud
	}
	if n.Delivery.DeliveryMethod != "" {
		if c.Delivery.DeliveryMethod != n.Delivery.DeliveryMethod {
			ismodified = true
			c.Delivery = n.Delivery
		}
	}
	if n.Delivery.URL != "" {
		if c.Delivery.URL != n.Delivery.URL {
			ismodified = true
			c.Delivery = n.Delivery
		}
	}
	if len(n.EventsSupported) > 0 && len(c.EventsSupported) != len(n.EventsSupported) {
		c.EventsSupported = n.EventsSupported
	}
	if len(n.EventsRequested) > 0 {
		ne := n.EventsRequested
		ce := c.EventsRequested
		for _, e := range ne {
			if !contains(ce, e) {
				ismodified = true
				ce = append(ce, e)
			}
		}
	}
	if len(n.EventsDelivered) > 0 && len(c.EventsDelivered) != len(n.EventsDelivered) {
		c.EventsDelivered = n.EventsDelivered
	}
	return ismodified
}

type ReqAddSub struct {
	Sub struct {
		SubType string `json:"subject_type"`
		SpagID  string `json:"spag_id"`
	} `json:"subject"`
	ReqEventScopes map[string][]string `json:"events_scopes_requested"`
}

// func (set *SETClaim) ToSubAndCtx() (spagID string, c *Context) {
// 	for id, eClaim := range set.Events {
// 		return eClaim.Subject.SpagID, &Context{
// 			Issuer:      set.Iss,
// 			ID:          id,
// 			ScopeValues: eClaim.Property,
// 		}
// 	}
// 	return "", nil
// }

type SSEEventClaim struct {
	ID      string `json:"-"`
	Subject struct {
		SubType string `json:"subject_type"`
		SpagID  string `json:"spag_id"`
	} `json:"subject"`
	Property map[string]string `json:"property"`
}

func NewSETEventsClaimFromJson(v interface{}) (*SSEEventClaim, bool) {
	v2, ok := v.(map[string]interface{})
	if !ok {
		return nil, false
	}
	for k, v := range v2 {
		v, ok := v.(map[string]interface{})
		if !ok {
			return nil, false
		}
		s, ok := v["subject"].(map[string]interface{})
		if !ok {
			return nil, false
		}
		p := make(map[string]string)
		p2, ok := v["property"].(map[string]interface{})
		if !ok {
			return nil, false
		}
		for pk, pv := range p2 {
			p[pk], ok = pv.(string)
			if !ok {
				return nil, false
			}
		}
		return &SSEEventClaim{
			ID: k,
			Subject: struct {
				SubType string "json:\"subject_type\""
				SpagID  string "json:\"spag_id\""
			}{s["subject_type"].(string), s["spag_id"].(string)},
			Property: p,
		}, true
	}
	return nil, false
}

func (e *SSEEventClaim) toClaim() map[string]SSEEventClaim {
	return map[string]SSEEventClaim{
		e.ID: *e,
	}
}

// func NewSETEventsClaim(spagID string, c *Context) map[string]EventClaim {
// 	eClaim := EventClaim{
// 		ID: c.ID,
// 		Subject: struct {
// 			SubType string "json:\"subject_type\""
// 			SpagID  string "json:\"spag_id\""
// 		}{"spag", spagID},
// 		Property: c.ScopeValues,
// 	}
// 	return map[string]EventClaim{
// 		eClaim.ID: eClaim,
// 	}
// }
