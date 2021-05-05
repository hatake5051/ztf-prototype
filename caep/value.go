package caep

import (
	"encoding/json"
	"fmt"
	"log"
	"mime"
	"net/http"
	"net/url"
	"path"
)

// Transmitter は caep Transmitter の設定情報を表す
type Transmitter struct {
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

// NewTransmitter は caep transmitter の well-known から取得して Trasmitter を構築する
func NewTransmitter(issuer string) (*Transmitter, error) {
	// well-knoenw url を構築
	url, err := url.Parse(issuer)
	if err != nil {
		log.Printf("CAEP Transmitter の issuer url parse に失敗: %v\n", err)
		return nil, err
	}
	url.Path = path.Join("/.well-known/sse-configuration", url.Path)

	// get method
	resp, err := http.Get(url.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// response error check
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
	// response parse
	tx := new(Transmitter)
	if err := json.NewDecoder(resp.Body).Decode(tx); err != nil {
		return nil, err
	}
	if tx.Issuer != issuer {
		return nil, fmt.Errorf("caep: issuer did not match the issuer returned by provider, expected %q got %q", issuer, tx.Issuer)
	}
	return tx, nil
}

// RxID は Receiver の識別子であり、 Transmitter が管理している
type RxID string

// Receiver は CAEP Transmitter が管理する Receiver 情報を表す
type Receiver struct {
	// ID は Transmitter における Receiver の識別子
	ID RxID
	// Host は Receiver のホスト名
	Host string
	// StreamConf は最も最近の Stream COnfig 情報を持つ
	StreamConf *StreamConfig
}

// StreamStatus は caep.EventStreamStatus を表す
type StreamStatus struct {
	// Status はそのユーザに対する Stream Status を表す
	Status string `json:"status"`
	// SpagID はユーザの識別子
	Subject EventSubject `json:"subject"`
	// EventScopes はそのユーザに対する Stream で提供されるコンテキストとそのスコープを表す
	// CAEP に対する独自拡張
	EventScopes map[EventType][]EventScope `json:"events_scopes"`
}

// ReqChangeOfStreamStatus は CAEP Receiver が Stream Status 変更要求する時のリクエストを表す
type ReqChangeOfStreamStatus struct {
	StreamStatus
	// Authorization はユーザの認可を表すトークン
	Authorization string `json:"authorization"`
	// Reason は Status 変更要求の理由を伝えることができる
	Reason string `json:"reason"`
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

// Update は StreamConfig を引数のもので上書きする
// 上書きした結果、元の StreamConfig から変更があると ismodified が true になる
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
		c.EventsRequested = ce
	}
	if len(n.EventsDelivered) > 0 && len(c.EventsDelivered) != len(n.EventsDelivered) {
		c.EventsDelivered = n.EventsDelivered
	}
	return ismodified
}

// ReqAddSub は Stream にユーザを追加要求する時のリクエストを表す
// Stream にユーザが追加されることでそのユーザのコンテキストを受け取ることができる
type ReqAddSub struct {
	// Sub は Stream に追加したいユーザ情報を表す
	// この識別子を Tx は理解できないので、 ReqEventScopes にある EventID から
	// Tx におけるこの Subject を識別する
	Subject *EventSubject `json:"subject"`
	// ReqEventScopes はどのコンテキストをどの粒度で求めるかを表す
	ReqEventScopes map[EventType]struct {
		EventID string       `json:"event_id"`
		Scopes  []EventScope `json:"scopes"`
	} `json:"events_scopes_requested"`
}

// EventSubject は 誰に関する Event であるか表現する
type EventSubject struct {
	User   map[string]string `json:"user"`
	Device map[string]string `json:"device,omitempty"`
}

func (s *EventSubject) Identifier() string {
	var format string
	for k, v := range s.User {
		if k == "format" {
			format = v
			break
		}
	}
	return s.User[format]
}

// EventType は Event の種類を表現する
type EventType string

// EventScope は Event のスコープを表現する
type EventScope string

// EventClaim は Security Event Token 上でやり取りされる Event を表現する
type Event struct {
	Type     EventType
	Subject  *EventSubject
	Property map[EventScope]string
}

func NewEventFromJSON(events interface{}) (e *Event, ok bool) {
	es, ok := events.(map[string]interface{})
	if !ok {
		return nil, false
	}
	for t, e := range es {
		e2, ok := e.(map[string]interface{})
		if !ok {
			return nil, false
		}
		sub := new(EventSubject)
		prop := make(map[EventScope]string)
		for k, v := range e2 {
			if k == "subject" {
				ss, ok := v.(map[string]interface{})
				if !ok {
					return nil, false
				}
				for k, v := range ss {
					if k == "user" {
						vv, ok := v.(map[string]interface{})
						if !ok {
							return nil, false
						}
						users := make(map[string]string)
						for kkk, vvv := range vv {
							users[kkk] = vvv.(string)
						}
						sub.User = users

					} else if k == "device" {
						vv, ok := v.(map[string]interface{})
						if !ok {
							return nil, false
						}
						devices := make(map[string]string)
						for kkk, vvv := range vv {
							devices[kkk] = vvv.(string)
						}
						sub.Device = devices
					}
				}
				continue
			}
			s, ok := v.(string)
			if !ok {
				return nil, false
			}
			prop[EventScope(k)] = s
		}

		return &Event{
			Type:     EventType(t),
			Subject:  sub,
			Property: prop,
		}, true
	}
	return nil, false
}

func (e *Event) ToClaim() map[string]map[string]interface{} {
	a := make(map[string]interface{})
	a["subject"] = e.Subject
	for k, v := range e.Property {
		a[string(k)] = v
	}
	return map[string]map[string]interface{}{
		string(e.Type): a,
	}
}
