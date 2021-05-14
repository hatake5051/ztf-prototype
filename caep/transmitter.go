package caep

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

// TransConf は caep の Transmitter を構築するための設定情報を表す
type TxConf struct {
	Tr *TransmitterConf
}

// New は設定情報から caep の txansmitter を構築する
func (c *TxConf) New(stream StreamConfigRepo, status SubStatusRepo, verifier Verifier) Tx {
	return &tx{
		c.Tr,
		stream,
		status,
		verifier,
	}
}

// Tr は CAEP の Transmitter を表す
type Tx interface {
	// Router は CAEP Transmitter Endpoint を mux.Router に構築する
	Router(r *mux.Router)
	// WellKnown は
	WellKnown(w http.ResponseWriter, r *http.Request)
	// Transmit は aud に event を送信する
	Transmit(context context.Context, aud RxID, event *Event) error
}

// RxRepo は Transmitter が管理している Receiver を永続化する
type StreamConfigRepo interface {
	// LoadStream は RxID に対応する Receiver の設定情報を読み出す
	LoadStream(RxID) (*StreamConfig, error)
	// SaveStream は Reveiver の設定情報を保存する
	SaveStream(RxID, *StreamConfig) error
}

// SubStatusRepo は Transmitter が管轄している Receiver のサブジェクトごとの status を永続化する
type SubStatusRepo interface {
	LoadStatus(RxID, *EventSubject) (*StreamStatus, error)
	SaveStatus(RxID, *StreamStatus) error
}

// Verifier は Receiver が Event Stream Management API を叩く時の認可情報を検証する
// また、認可情報から recveiver を識別する
// Status のときは ReqChangeOfStreamStatus の認可情報を見てそれに基づいて更新した status を返す
// AddSub のときは ReqAddSub を authHeader の認可情報を見てそれに基づいて更新した status を返す
type Verifier interface {
	Stream(authHeader string) (RxID, error)
	Status(authHeader string, req *ReqChangeOfStreamStatus) (RxID, *StreamStatus, error)
	AddSub(authHeader string, req *ReqAddSub) (RxID, *StreamStatus, error)
}

type tx struct {
	conf     *TransmitterConf
	stream   StreamConfigRepo
	status   SubStatusRepo
	verifier Verifier
}

func (tx *tx) Router(r *mux.Router) {
	r.PathPrefix("/sse/mgmt/stream").Methods("GET").HandlerFunc(tx.ReadStreamConfig)
	r.PathPrefix("/sse/mgmt/stream").Methods("POST").HandlerFunc(tx.UpdateStreamConfig)
	r.PathPrefix("/sse/mgmt/status").Methods("GET").HandlerFunc(tx.ReadStreamStatus)
	r.PathPrefix("/sse/mgmt/subject:add").Methods("POST").HandlerFunc(tx.AddSub)
}

func (tx *tx) WellKnown(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(tx.conf); err != nil {
		http.Error(w, "失敗", http.StatusInternalServerError)
		return
	}
}

func (tx *tx) ReadStreamStatus(w http.ResponseWriter, r *http.Request) {
	// Token の検証をして、対応する Receiver を識別する (Sec.9)
	rxID, _, err := tx.verifier.Status(r.Header.Get("Authorization"), nil)
	if err != nil {
		if err, ok := err.(TxError); ok {
			if err.Code() == TxErrorUnAuthorized {
				headers := err.Option().(map[string]string)
				for k, v := range headers {
					w.Header().Set(k, v)
				}
			}
		}
		fmt.Printf("[CAEP] Tx.ReadStreamStatus failed because validation %#v\n", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// どのユーザの status を調べようとしているかチェック
	if err := r.ParseForm(); err != nil {
		http.Error(w, "リクエストのパースに失敗 "+err.Error(), http.StatusInternalServerError)
		return
	}
	sub := new(EventSubject)
	b, err := base64.RawURLEncoding.DecodeString(r.Form.Get("subject"))
	if err != nil {
		http.Error(w, "get stream status の subject クエリが正しくないフォーマット"+err.Error(), http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(b, sub); err != nil {
		http.Error(w, "get stream status の subject クエリが正しくないフォーマット"+err.Error(), http.StatusBadRequest)
		return
	}
	status, err := tx.status.LoadStatus(rxID, sub)
	if err != nil {
		fmt.Printf("[CAEP] Tx.ReadStreamStatus failed because not found %#v\n", err)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		http.Error(w, "失敗", http.StatusInternalServerError)
		return
	}
	fmt.Printf("[CAEP] Tx.ReamStreamStatus succeeded status: %#v\n", status)
}

func (tx *tx) UpdateStreamStatus(w http.ResponseWriter, r *http.Request) {
	// 要求をパースする
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if contentType != "application/json" {
		http.Error(w, "unmached content-type", http.StatusBadRequest)
		return
	}
	reqStatus := new(ReqChangeOfStreamStatus)
	if err := json.NewDecoder(r.Body).Decode(reqStatus); err != nil {
		http.Error(w, "status update 要求のパースに失敗", http.StatusNotFound)
		return
	}
	// Token の検証をして、対応する Receiver を識別する (Sec.9)
	rxID, status, err := tx.verifier.Status(r.Header.Get("Authorization"), reqStatus)
	if err != nil {
		if err, ok := err.(TxError); ok {
			if err.Code() == TxErrorUnAuthorized {
				headers := err.Option().(map[string]string)
				for k, v := range headers {
					w.Header().Set(k, v)
				}
			}
		}
		fmt.Printf("[CAEP] Tx.UpdatetreamStatus failed because validation %#v\n", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := tx.status.SaveStatus(rxID, status); err != nil {
		fmt.Printf("[CAEP] Tx.UpdatetreamStatus failed because status.Save(%s,%v) %#v\n", rxID, status, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Printf("[CAEP] Tx.UpdatetreamStatus succeeded status %#v\n", status)
}

func (tx *tx) ReadStreamConfig(w http.ResponseWriter, r *http.Request) {
	// Token の検証をして、対応する Receiver を識別する
	rxID, err := tx.verifier.Stream(r.Header.Get("Authorization"))
	if err != nil {
		if err, ok := err.(TxError); ok {
			if err.Code() == TxErrorUnAuthorized {
				headers := err.Option().(map[string]string)
				for k, v := range headers {
					w.Header().Set(k, v)
				}
			}
		}
		fmt.Printf("[CAEP] Tx.ReadStreamConfig failed because validation %#v\n", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	stream, err := tx.stream.LoadStream(rxID)
	if err != nil {
		fmt.Printf("[CAEP] Tx.ReadStreamConfig failed because stream.Load(%s) %#v\n", rxID, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stream); err != nil {
		http.Error(w, "失敗", http.StatusInternalServerError)
		return
	}
	fmt.Printf("[CAEP] Tx.ReadStreamConfig succeeded stream %#v\n", stream)
}

func (tx *tx) UpdateStreamConfig(w http.ResponseWriter, r *http.Request) {
	// Token の検証をして、対応する Receiver を識別する
	rxID, err := tx.verifier.Stream(r.Header.Get("Authorization"))
	if err != nil {
		if err, ok := err.(TxError); ok {
			if err.Code() == TxErrorUnAuthorized {
				headers := err.Option().(map[string]string)
				for k, v := range headers {
					w.Header().Set(k, v)
				}
			}
		}
		fmt.Printf("[CAEP] Tx.UpdatetreamConfig failed because validation %#v\n", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	req := new(StreamConfig)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		http.Error(w, "status update 要求のパースに失敗", http.StatusNotFound)
		return
	}
	stream, err := tx.stream.LoadStream(rxID)
	if err != nil {
		fmt.Printf("[CAEP] Tx.UpdatetreamConfig failed because stream.Load(%s) %#v\n", rxID, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ismodified := stream.update(req); ismodified {
		for _, e := range stream.EventsRequested {
			if contains(stream.EventsSupported, e) {
				stream.EventsDelivered = append(stream.EventsDelivered, e)
			}
		}
		if err := tx.stream.SaveStream(rxID, stream); err != nil {
			fmt.Printf("[CAEP] Tx.UpdatetreamConfig failed because stream.Save(%s, %v) %#v\n", rxID, stream, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stream); err != nil {
		http.Error(w, "失敗", http.StatusInternalServerError)
		return
	}
	fmt.Printf("[CAEP] Tx.UpdatetreamConfig succeeded stream %#v\n", stream)
}

func (tx *tx) AddSub(w http.ResponseWriter, r *http.Request) {
	// 要求をパースする
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if contentType != "application/json" {
		http.Error(w, "unmached content-type", http.StatusBadRequest)
		return
	}
	req := new(ReqAddSub)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		http.Error(w, fmt.Sprintf("フォーマットに失敗 %v", err), http.StatusBadRequest)
		return
	}

	// Token の検証をして、対応する Receiver を識別する (Sec.9)
	rxID, status, err := tx.verifier.AddSub(r.Header.Get("Authorization"), req)
	if err != nil {
		if err, ok := err.(TxError); ok {
			if err.Code() == TxErrorUnAuthorized {
				headers := err.Option().(map[string]string)
				for k, v := range headers {
					w.Header().Set(k, v)
				}
				fmt.Printf("[CAEP] Tx.AddSub failed(401) because validation %#v\n", err)
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			if err.Code() == TxErrorNotFound {
				fmt.Printf("[CAEP] Tx.AddSub failed(404) because validation %#v\n", err)
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
		}
		fmt.Printf("[CAEP] Tx.AddSub failed(403) because validation %#v\n", err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := tx.status.SaveStatus(rxID, status); err != nil {
		fmt.Printf("[CAEP] Tx.AddSub failed because status.Save(%s,%v) %#v\n", rxID, status, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Printf("[CAEP] Tx.AddSub succeeded %#v\n", status)
	return
}

func (tx *tx) Transmit(context context.Context, aud RxID, event *Event) error {
	t := jwt.New()
	t.Set(jwt.IssuerKey, tx.conf.Issuer)
	stream, err := tx.stream.LoadStream(aud)
	if err != nil {
		fmt.Printf("[CAEP] Tx.Transmit failed because stream.Load(%s) %#v\n", aud, err)
		return fmt.Errorf("invalid rxID(%v) %w", aud, err)
	}
	t.Set(jwt.AudienceKey, stream.Aud)
	t.Set(jwt.IssuedAtKey, time.Now())
	b := make([]byte, 256)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("cannot generate random bytes %w", err)
	}
	jti := base64.RawURLEncoding.EncodeToString(b)
	t.Set(jwt.JwtIDKey, jti)
	t.Set("events", event.ToClaim())

	ss, err := jwt.Sign(t, jwa.HS256, []byte("secret-hs-256-key"))
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(context, http.MethodPost, stream.Delivery.URL, bytes.NewBuffer(ss))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/secevent+jwt")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("[CAEP] Tx.Transmit failed because http.Do %#v\n", err)
		return err
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("[CAEP] Tx.Transmit failed because http.Do statusCode %#v\n", resp.Status)
		return fmt.Errorf("respons status code unmatched : %v", resp.Status)
	}
	fmt.Printf("[CAEP] Tx.Transmit succeeded with event: %#v \n", ss)
	return nil
}

type TxError interface {
	error
	Code() TxErrorCode
	Option() interface{}
}

type TxErrorCode int

const (
	// TxErrorUnAuthorized は 401 error
	// option として *http.Response が含まれるが、Body は読めない
	TxErrorUnAuthorized TxErrorCode = 401
	// TxErrorNotFound は 404 error
	TxErrorNotFound TxErrorCode = 403
)
