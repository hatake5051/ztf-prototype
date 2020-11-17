package caep

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"mime"
	"net/http"
	"net/http/httputil"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/hatake5051/ztf-prototype/uma"

	"golang.org/x/oauth2"
)

// UpdateCtxsRequested は reqctxIDs を caep.EventStreamConfiguration.events_requested が含んでいるか確認する。
// 含んでいなければ、含んでいない ctxID を events_requested に追加する
func (config *CtxStreamConfig) UpdateCtxsRequested(reqctxIDs []string) (ismodified bool) {
	if len(reqctxIDs) == 0 {
		return
	}

	var lackctxNames []string
	for _, id := range reqctxIDs {
		if !contains(config.EventsRequested, id) {
			lackctxNames = append(lackctxNames, id)
			ismodified = true
		}
	}
	if ismodified {
		config.EventsRequested = append(config.EventsRequested, lackctxNames...)
	}
	return ismodified
}

// RecvError は error を表す
type RecvError interface {
	error
	Code() RecvErrorCode
}

// RecvErrorCode は error の種別を表す
type RecvErrorCode int

const (
	_ RecvErrorCode = iota
	// FailedToReadCtxStream は 404 error
	FailedToReadCtxStream
	// FailedToUpdateCtxStream は stream config update に失敗したことを示す
	FailedToUpdateCtxStream
	// NoOAuthTokenForConfigStream は Config のためのトークンがないことを示す
	NoOAuthTokenForConfigStream
	FailedToReadCtxStreamStatus
	FailedToAddSubject
	UMAUnAuthorizedWithPermissionTicket
)

// Recv は caep.Receiver の働きをする
type Recv interface {
	// DefaultCtxStreamConfig は recver の静的なデフォルトの設定情報を取得する
	DefaultCtxStreamConfig() *CtxStreamConfig
	// ReadCtxsStream は Get /set/stream する
	ReadCtxStream() (*CtxStreamConfig, error)
	// UpdateCtxStream は conf を POST /set/stream する
	UpdateCtxStream(conf *CtxStreamConfig) (*CtxStreamConfig, error)
	// ReadCtxStreamStatus は Get /set/status/{spag_id} する
	ReadCtxStreamStatus(spagID string) (*CtxStreamStatus, error)
	// UpdateCtxStreamStatus(status *CtxStreamStatus) error
	// AddSubject は POST /set/subjects:add する
	AddSubject(spadID string, reqctxs []Context) error
	// Recv は コンテキストを受け取る
	Recv(*http.Request) error
}

// RecvConf は caep の Receiver の設定情報を表す
type RecvConf struct {
	// host は Receiver のホスト名
	Host string
	// RecvCtxEndpoint は Ctx を受け取るエンドポイント
	RecvCtxEndpoint string
	// Issuer は Transmitter のホスト名
	Issuer string
}

// New は Recv を返す
// t は stream config/status endpoit の保護に使う OAuth-AccessToken を保持
// uc は sub add endpoint の保護に使う UMA-RPT を保持
// set は receive event を context に変換して保存する
func (conf *RecvConf) New(t *oauth2.Token, uc UMAClient, set SetCtx) (Recv, error) {
	tr, err := NewTransmitter(conf.Issuer)
	if err != nil {
		return nil, err
	}
	return &recv{tr, conf.Host, conf.RecvCtxEndpoint, t, uc, set}, nil
}

// SetCtx は caep Receiver が受け取ったコンテキストを PIP で保存する
type SetCtx func(spagID string, c *Context) error

// UMAClient は Add SUbject するときの UMA AUthz Grant Flow を担う
type UMAClient interface {
	// ExtractPermissionTicket は RPT がない/有効でない時にレスポンスされる permission ticket を抽出する
	ExtractPermissionTicket(spagID string, resp *http.Response) error
	// RPT は spagID の RPT があレバそれを返す
	RPT(spagID string) (*uma.RPT, error)
}

type recv struct {
	// tr は caep.Transmitter の設定情報を含む
	tr *Transmitter
	// host は この recv の host を表す
	host string
	// recvCtxEndpoint は event-pushed-endpoint を表す
	recvCtxEndpoint string
	// recvOauth は stream config/status endpoit の保護に使う OAuth-AccessToken を保持
	configToken *oauth2.Token
	// umaClient は sub add endpoint の保護に使う UMA-RPT を保持
	umaClient UMAClient
	// set は receive event を context に変換して保存する
	set SetCtx
}

func (recv *recv) DefaultCtxStreamConfig() *CtxStreamConfig {
	return &CtxStreamConfig{
		Aud: []string{recv.host},
		Delivery: struct {
			DeliveryMethod string `json:"delivery_method"`
			URL            string `json:"url"`
		}{"https://schemas.openid.net/secevent/risc/delivery-method/push", recv.recvCtxEndpoint},
	}
}

func (recv *recv) ReadCtxStream() (*CtxStreamConfig, error) {
	req, err := http.NewRequest("GET", recv.tr.ConfigurationEndpoint, nil)
	if err != nil {
		return nil, err
	}
	if recv.configToken == nil {
		return nil, &cscerr{err, NoOAuthTokenForConfigStream}
	}
	recv.configToken.SetAuthHeader(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, &cscerr{fmt.Errorf("error status code %d", resp.StatusCode), NoOAuthTokenForConfigStream}
	}
	if resp.StatusCode == http.StatusNotFound {

		return nil, &cscerr{fmt.Errorf("read status with statuscode: 404"), FailedToReadCtxStream}
	}
	defer resp.Body.Close()
	var c CtxStreamConfig
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil

}

func (recv *recv) UpdateCtxStream(conf *CtxStreamConfig) (*CtxStreamConfig, error) {
	bodyJSON, err := json.Marshal(conf)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", recv.tr.ConfigurationEndpoint, bytes.NewBuffer(bodyJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	if recv.configToken == nil {
		return nil, &cscerr{err, NoOAuthTokenForConfigStream}
	}
	recv.configToken.SetAuthHeader(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		dump, _ := httputil.DumpResponse(resp, true)
		log.Printf("event stream config post failed, resp dump: %s\n", string(dump))
		return nil, &cscerr{fmt.Errorf("config post failed statuscode: %d", resp.StatusCode), FailedToUpdateCtxStream}
	}
	defer resp.Body.Close()
	var c CtxStreamConfig
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (recv *recv) ReadCtxStreamStatus(spagID string) (*CtxStreamStatus, error) {
	url := recv.tr.StatusEndpoint
	if spagID != "" {
		url = url + "/" + spagID
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if recv.configToken == nil {
		return nil, &cscerr{fmt.Errorf("recv.configToken がありません！！！"), NoOAuthTokenForConfigStream}
	}
	recv.configToken.SetAuthHeader(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &cscerr{fmt.Errorf("read ctx stream status failed statuscode: %v", resp.StatusCode), FailedToReadCtxStreamStatus}
	}
	defer resp.Body.Close()
	var c CtxStreamStatus
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (recv *recv) AddSubject(spagID string, reqctxs []Context) error {
	ctxsReqJSON := make(map[string]interface{})
	for _, c := range reqctxs {
		ctxsReqJSON[c.ID] = c.Scopes
	}
	body := map[string]interface{}{
		"subject": map[string]string{
			"subject_type": "spag",
			"spag_id":      spagID,
		},
		"events_scopes_requested": ctxsReqJSON,
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", recv.tr.AddSubjectEndpoint, bytes.NewBuffer(bodyJSON))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	if t, err := recv.umaClient.RPT(spagID); err == nil {
		t.SetAuthHeader(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		recv.umaClient.ExtractPermissionTicket(spagID, resp)
		return &cscerr{fmt.Errorf("%s:%s", spagID, "permission-ticket"), UMAUnAuthorizedWithPermissionTicket}
	}
	if resp.StatusCode != http.StatusOK {
		return &cscerr{fmt.Errorf("config post failed statuscode: %v", resp.StatusCode), FailedToAddSubject}
	}
	return nil
}

func (recv *recv) Recv(r *http.Request) error {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return err
	}
	if contentType != "application/secevent+jwt" {
		return err
	}

	defer r.Body.Close()
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	tok, err := jwt.ParseWithClaims(string(b), &SETClaim{}, func(t *jwt.Token) (interface{}, error) {
		// TODO: ベタガキをやめよう
		return []byte("secret-hs256-key"), nil
	})
	if set, ok := tok.Claims.(*SETClaim); ok && tok.Valid {
		return recv.set(set.ToSubAndCtx())
	}
	return err
}

var _ RecvError = &cscerr{}

// cscerr は CtxStreamConfigError を実装する
type cscerr struct {
	error
	code RecvErrorCode
}

func (e *cscerr) Code() RecvErrorCode {
	return e.code
}

func contains(src []string, x string) bool {
	for _, name := range src {
		if name == x {
			return true
		}
	}
	return false
}
