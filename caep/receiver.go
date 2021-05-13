package caep

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"sync"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

// RXConf は caep の Receiver を構築するための設定情報を表す
type RxConf struct {
	// host は Receiver のホスト名
	Host url.URL
	// RecvEndpoint は  を受け取るエンドポイント
	RecvEndpoint url.URL
	// Issuer は Transmitter のホスト名
	Issuer url.URL
}

// New は Recv を返す
// t は stream config/status endpoit の保護に使う OAuth-AccessToken を保持
// uc は sub add endpoint の保護に使う UMA-RPT を保持
// set は receive event を context に変換して保存する
func (conf *RxConf) New() Rx {
	tr, err := NewTransmitterConf(&conf.Issuer)
	if err != nil {
		panic(fmt.Sprintf("Transmitterの設定情報の取得に失敗 from %s %v", conf.Issuer, err))
	}

	return &rx{
		tr: tr,
		sconf: &StreamConfig{
			Delivery: struct {
				DeliveryMethod string `json:"delivery_method"`
				URL            string `json:"url"`
			}{"https://schemas.openid.net/secevent/risc/delivery-method/push", conf.RecvEndpoint.String()},
		},
	}
}

// Rx は caep.Receiver の働きをする
type Rx interface {
	// SetUpStream は StreamConfig を最新のものにして、更新も行う
	SetUpStream(client *http.Client, conf *StreamConfig) error
	// ReadStreamStatus は Subject に関する現在の Status を確認する
	ReadStreamStatus(client *http.Client, sub *EventSubject) (*StreamStatus, error)
	// UpdateStreamStatus(status *StreamStatus) error
	// AddSubject は POST /set/subjects:add する
	AddSubject(client *http.Client, reqAddSub *ReqAddSub) error
	// Recv は イベントを受け取る
	Recv(*http.Request) (*Event, error)
}

type rx struct {
	// tr は caep.Transmitter の設定情報を含む
	tr *TransmitterConf
	// recv は Receiver の設定情報を持つ。
	sconf *StreamConfig
	m     sync.RWMutex
}

func (rx *rx) SetUpStream(client *http.Client, conf *StreamConfig) error {
	srvSavedConf, err := rx.ReadStream(client)
	if err != nil {
		return err
	}
	rx.m.RLock()
	defer rx.m.RUnlock()
	_ = rx.sconf.update(srvSavedConf)
	_ = rx.sconf.update(conf)
	ismodified := srvSavedConf.update(rx.sconf)
	if ismodified {
		newSrvSavedConf, err := rx.UpdateStream(client, rx.sconf)
		if err != nil {
			return err
		}
		_ = rx.sconf.update(newSrvSavedConf)
	}

	return nil
}

func (rx *rx) ReadStream(client *http.Client) (*StreamConfig, error) {
	req, err := http.NewRequest("GET", rx.tr.ConfigurationEndpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, newEO(fmt.Errorf("401"), RecvErrorCodeUnAuthorized, resp)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("read event stream status failed with statuscode: %v", resp.StatusCode)
	}
	c := new(StreamConfig)
	if err := json.NewDecoder(resp.Body).Decode(c); err != nil {
		return nil, err
	}
	return c, nil
}

func (rx *rx) UpdateStream(client *http.Client, conf *StreamConfig) (*StreamConfig, error) {
	bodyJSON, err := json.Marshal(conf)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", rx.tr.ConfigurationEndpoint, bytes.NewBuffer(bodyJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, newEO(fmt.Errorf("401"), RecvErrorCodeUnAuthorized, resp)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update event stream failed with statuscode: %d", resp.StatusCode)
	}
	var c StreamConfig
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (rx *rx) ReadStreamStatus(client *http.Client, sub *EventSubject) (*StreamStatus, error) {
	// Event Subject を base64url encode して query に埋め込む
	b, err := json.Marshal(sub)
	if err != nil {
		return nil, err
	}
	pidStr := base64.RawURLEncoding.EncodeToString(b)

	url, err := url.Parse(rx.tr.StatusEndpoint)
	if err != nil {
		return nil, err
	}
	q := url.Query()
	q.Add("subject", pidStr)
	url.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, newEO(fmt.Errorf("401"), RecvErrorCodeUnAuthorized, resp)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("read read stream status about subject(%#v) failed with statuscode: %v", sub, resp.StatusCode)
	}
	s := new(StreamStatus)
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, err
	}
	return s, nil
}

func (rx *rx) AddSubject(client *http.Client, reqadd *ReqAddSub) error {
	bodyJSON, err := json.Marshal(reqadd)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", rx.tr.AddSubjectEndpoint, bytes.NewBuffer(bodyJSON))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return newEO(fmt.Errorf("UMA 401"), RecvErrorCodeUnAuthorized, resp)
	}
	if resp.StatusCode == http.StatusNotFound {
		return newE(fmt.Errorf("CAEP 404"), RecvErrorCodeNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("config post failed statuscode: %v", resp.StatusCode)
	}
	return nil
}

func (rx *rx) Recv(r *http.Request) (*Event, error) {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	if contentType != "application/secevent+jwt" {
		return nil, err
	}

	tok, err := jwt.Parse(r.Body, jwt.WithVerify(jwa.HS256, []byte("secret-hs-256-key")))
	if err != nil {
		return nil, err
	}
	rx.m.RLock()
	defer rx.m.RUnlock()
	if err := jwt.Verify(tok, jwt.WithAudience(rx.sconf.Aud), jwt.WithIssuer(rx.tr.Issuer)); err != nil {
		return nil, err
	}
	v, ok := tok.Get("events")
	if !ok {
		return nil, fmt.Errorf("送られてきたSETに events がない")
	}
	e, ok := NewEventFromJSON(v)
	if !ok {
		return nil, fmt.Errorf("送られてきたSET events (%#v) のパースに失敗 ", v)
	}
	return e, nil
}

// RecvError は error を表す
type RecvError interface {
	error
	Code() RecvErrorCode
	Option() interface{}
}

// RecvErrorCode は error の種別を表す
type RecvErrorCode int

const (
	// RecvErrorUnAuthorized は 401 error
	// option として *http.Response が含まれるが、Body は読めない
	RecvErrorCodeUnAuthorized RecvErrorCode = 401
	// RecvErrorCodeNotFound は 404 error
	RecvErrorCodeNotFound RecvErrorCode = 404
)

func newE(err error, code RecvErrorCode) RecvError {
	return &cscerr{err, code, nil}
}

func newEO(err error, code RecvErrorCode, opt interface{}) RecvError {
	return &cscerr{err, code, opt}
}

// cscerr は StreamConfigError を実装する
type cscerr struct {
	error
	code   RecvErrorCode
	option interface{}
}

func (e *cscerr) Code() RecvErrorCode {
	return e.code
}

func (e *cscerr) Option() interface{} {
	return e.option
}
