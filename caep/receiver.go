package caep

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"path"
	"sync"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

// RecvConf は caep の Receiver を構築するための設定情報を表す
type RecvConf struct {
	// host は Receiver のホスト名
	Host string
	// RecvEndpoint は  を受け取るエンドポイント
	RecvEndpoint string
	// Issuer は Transmitter のホスト名
	Issuer string
}

// New は Recv を返す
// t は stream config/status endpoit の保護に使う OAuth-AccessToken を保持
// uc は sub add endpoint の保護に使う UMA-RPT を保持
// set は receive event を context に変換して保存する
func (conf *RecvConf) New(authHeadersetter AuthHeaderSetter) Rx {
	tr, err := NewTransmitter(conf.Issuer)
	if err != nil {
		panic(fmt.Sprintf("Transmitterの設定情報の取得に失敗 %v", err))
	}
	r := &recvConf{
		data: Receiver{
			Host: conf.Host,
			StreamConf: &StreamConfig{
				Delivery: struct {
					DeliveryMethod string `json:"delivery_method"`
					URL            string `json:"url"`
				}{"https://schemas.openid.net/secevent/risc/delivery-method/push", conf.RecvEndpoint},
			},
		},
	}
	return &rx{
		tr:           tr,
		recv:         r,
		setAuthHeder: authHeadersetter,
	}
}

// Rx は caep.Receiver の働きをする
type Rx interface {
	// SetUpStream は StreamConfig を最新のものにして、更新も行う
	SetUpStream(conf *StreamConfig) error
	// ReadStreamStatus は Subject に関する現在の Status を確認する
	ReadStreamStatus(*EventSubject) (*StreamStatus, error)
	// UpdateStreamStatus(status *StreamStatus) error
	// AddSubject は POST /set/subjects:add する
	AddSubject(*ReqAddSub) error
	// Recv は イベントを受け取る
	Recv(*http.Request) (*Event, error)
}

// AuthHeaderSetter は Receiver が Stream Mgmt API にアクセスする時のトークンを付与する
// 付与することができない時はそのまま
type AuthHeaderSetter interface {
	ForConfig(r *http.Request)
	ForSubAdd(*EventSubject, *http.Request)
}

type ReceiverConf interface {
	Load() (*Receiver, error)
	Save(*Receiver) error
}

type recvConf struct {
	data Receiver
	m    sync.RWMutex
}

func (c *recvConf) Load() (*Receiver, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	return &c.data, nil
}

func (c *recvConf) Save(r *Receiver) error {
	c.m.Lock()
	defer c.m.Unlock()
	c.data = *r
	return nil
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
	_ RecvErrorCode = iota + 400
	// RecvErrorUnAuthorized は 401 error
	// option として *http.Response が含まれるが、Body は読めない
	RecvErrorCodeUnAuthorized
	_
	_
	// RecvErrorCodeNotFound は 404 error
	RecvErrorCodeNotFound
)

type rx struct {
	// tr は caep.Transmitter の設定情報を含む
	tr *Transmitter
	// recv は Receiver の設定情報を持つ。
	recv ReceiverConf
	// recvOauth は stream config/status endpoit の保護に使う OAuth-AccessToken を保持
	setAuthHeder AuthHeaderSetter
}

func (rx *rx) ReadStreamStatus(sub *EventSubject) (*StreamStatus, error) {
	// Event Subject を base64url encode して query に埋め込む
	b, err := json.Marshal(sub)
	if err != nil {
		return nil, err
	}
	pidStr := base64.URLEncoding.EncodeToString(b)

	url, err := url.Parse(rx.tr.StatusEndpoint)
	if err != nil {
		return nil, err
	}
	url.Path = path.Join(url.Path, pidStr)

	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return nil, err
	}
	rx.setAuthHeder.ForConfig(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, newEO(fmt.Errorf("401"), RecvErrorCodeUnAuthorized, resp)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("read ctx stream status failed statuscode: %v", resp.StatusCode)
	}
	s := new(StreamStatus)
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, err
	}
	return s, nil
}

func (rx *rx) SetUpStream(conf *StreamConfig) error {
	srvSavedConf, err := rx.ReadStream()
	if err != nil {
		return err
	}
	recv, err := rx.recv.Load()
	if err != nil {
		return err
	}
	_ = recv.StreamConf.Update(srvSavedConf)
	_ = recv.StreamConf.Update(conf)
	ismodified := srvSavedConf.Update(recv.StreamConf)
	if ismodified {
		newSrvSavedConf, err := rx.UpdateStream(recv.StreamConf)
		if err != nil {
			return err
		}
		_ = recv.StreamConf.Update(newSrvSavedConf)
	}
	if err := rx.recv.Save(recv); err != nil {
		return err
	}

	return nil
}

func (rx *rx) ReadStream() (*StreamConfig, error) {
	req, err := http.NewRequest("GET", rx.tr.ConfigurationEndpoint, nil)
	if err != nil {
		return nil, err
	}
	rx.setAuthHeder.ForConfig(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, newEO(fmt.Errorf("401"), RecvErrorCodeUnAuthorized, resp)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("read ctx stream status failed statuscode: %v", resp.StatusCode)
	}
	c := new(StreamConfig)
	if err := json.NewDecoder(resp.Body).Decode(c); err != nil {
		return nil, err
	}
	return c, nil
}

func (rx *rx) UpdateStream(conf *StreamConfig) (*StreamConfig, error) {
	bodyJSON, err := json.Marshal(conf)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", rx.tr.ConfigurationEndpoint, bytes.NewBuffer(bodyJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	rx.setAuthHeder.ForConfig(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, newEO(fmt.Errorf("401"), RecvErrorCodeUnAuthorized, resp)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("config post failed statuscode: %d", resp.StatusCode)
	}
	var c StreamConfig
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (rx *rx) AddSubject(reqadd *ReqAddSub) error {
	bodyJSON, err := json.Marshal(reqadd)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", rx.tr.AddSubjectEndpoint, bytes.NewBuffer(bodyJSON))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	rx.setAuthHeder.ForSubAdd(reqadd.Subject, req)
	resp, err := http.DefaultClient.Do(req)
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
	recv, err := rx.recv.Load()
	if err != nil {
		return nil, err
	}
	if err := jwt.Verify(tok, jwt.WithAudience(recv.Host), jwt.WithIssuer(rx.tr.Issuer)); err != nil {
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

func contains(src []string, x string) bool {
	for _, name := range src {
		if name == x {
			return true
		}
	}
	return false
}
