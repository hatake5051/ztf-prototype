package caep

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/gorilla/mux"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

// TransConf は caep の Transmitter を構築するための設定情報を表す
type TransConf struct {
	Tr *Transmitter
}

// New は設定情報から caep の txansmitter を構築する
func (c *TransConf) New(rxRepo RxRepo, subStatusRepo SubStatusRepo, verifier Verifier) Tx {
	return &tx{
		conf:       c.Tr,
		rxRepo:     rxRepo,
		statusRepo: subStatusRepo,
		verifier:   verifier,
	}
}

// Tr は CAEP の Transmitter を表す
type Tx interface {
	// Router は CAEP Transmitter Endpoint を mux.Router に構築する
	Router(r *mux.Router)
	// WellKnown は
	WellKnown(w http.ResponseWriter, r *http.Request)
	// Transmit は aud に event を送信する
	Transmit(aud []Receiver, event *Event) error
}

// RxRepo は Transmitter が管理している Receiver を永続化する
type RxRepo interface {
	// Load は RxID に対応する Receiver の設定情報を読み出す
	Load(RxID) (*Receiver, error)
	// Save は Reveiver の設定情報を保存する
	Save(*Receiver) error
}

// SubStatusRepo は Transmitter が管轄している Receiver のサブジェクトごとの status を永続化する
type SubStatusRepo interface {
	Load(RxID, *EventSubject) (*StreamStatus, error)
	Save(RxID, *StreamStatus) error
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
	conf       *Transmitter
	rxRepo     RxRepo
	statusRepo SubStatusRepo
	verifier   Verifier
}

func (tx *tx) Router(r *mux.Router) {
	r.Use(DumpMiddleware)
	r.HandleFunc("/.well-known/sse-configuration", tx.WellKnown)

	u, err := url.Parse(tx.conf.ConfigurationEndpoint)
	if err != nil {
		panic("設定をミスってるよ" + err.Error())
	}
	r.PathPrefix(u.Path).Methods("GET").HandlerFunc(tx.ReadStreamConfig)
	r.PathPrefix(u.Path).Methods("POST").HandlerFunc(tx.UpdateStreamConfig)

	u, err = url.Parse(tx.conf.StatusEndpoint)
	if err != nil {
		panic("設定をミスってるよ" + err.Error())
	}
	r.PathPrefix(u.Path).Methods("GET").HandlerFunc(tx.ReadStreamStatus)

	u, err = url.Parse(tx.conf.AddSubjectEndpoint)
	if err != nil {
		panic("設定をミスってるよ" + err.Error())
	}
	r.PathPrefix(u.Path).Methods("POST").HandlerFunc(tx.AddSub)
}

func DumpMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := httputil.DumpRequest(r, true)
		fmt.Printf("DumpMiddlere\n%s\n", b)
		next.ServeHTTP(w, r)
	})
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
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// どのユーザの status を調べようとしているかチェック
	sub := new(EventSubject)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "リクエストのパースに失敗 "+err.Error(), http.StatusInternalServerError)
		return
	}
	b, err := base64.URLEncoding.DecodeString(r.Form.Get("subject"))
	if err != nil {
		http.Error(w, "get stream status の subject クエリが正しくないフォーマット"+err.Error(), http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(b, sub); err != nil {
		http.Error(w, "get stream status の subject クエリが正しくないフォーマット"+err.Error(), http.StatusBadRequest)
		return
	}
	status, err := tx.statusRepo.Load(rxID, sub)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		http.Error(w, "失敗", http.StatusInternalServerError)
		return
	}
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
	recvID, status, err := tx.verifier.Status(r.Header.Get("Authorization"), reqStatus)
	if err != nil {
		if err, ok := err.(TxError); ok {
			if err.Code() == TxErrorUnAuthorized {
				headers := err.Option().(map[string]string)
				for k, v := range headers {
					w.Header().Set(k, v)
				}
			}
		}
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := tx.statusRepo.Save(recvID, status); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (tx *tx) ReadStreamConfig(w http.ResponseWriter, r *http.Request) {
	// Token の検証をして、対応する Receiver を識別する
	recvID, err := tx.verifier.Stream(r.Header.Get("Authorization"))
	if err != nil {
		if err, ok := err.(TxError); ok {
			if err.Code() == TxErrorUnAuthorized {
				headers := err.Option().(map[string]string)
				for k, v := range headers {
					w.Header().Set(k, v)
				}
			}
		}
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	recv, err := tx.rxRepo.Load(recvID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(recv.StreamConf); err != nil {
		http.Error(w, "失敗", http.StatusInternalServerError)
		return
	}
}

func (tx *tx) UpdateStreamConfig(w http.ResponseWriter, r *http.Request) {
	// Token の検証をして、対応する Receiver を識別する
	recvID, err := tx.verifier.Stream(r.Header.Get("Authorization"))
	if err != nil {
		if err, ok := err.(TxError); ok {
			if err.Code() == TxErrorUnAuthorized {
				headers := err.Option().(map[string]string)
				for k, v := range headers {
					w.Header().Set(k, v)
				}
			}
		}
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	req := new(StreamConfig)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		http.Error(w, "status update 要求のパースに失敗", http.StatusNotFound)
		return
	}
	recv, err := tx.rxRepo.Load(recvID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ismodified := recv.StreamConf.Update(req); ismodified {
		for _, e := range recv.StreamConf.EventsRequested {
			if contains(recv.StreamConf.EventsSupported, e) {
				recv.StreamConf.EventsDelivered = append(recv.StreamConf.EventsDelivered, e)
			}
		}
		if err := tx.rxRepo.Save(recv); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(recv.StreamConf); err != nil {
		http.Error(w, "失敗", http.StatusInternalServerError)
		return
	}
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
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			if err.Code() == TxErrorNotFound {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
		}
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := tx.statusRepo.Save(rxID, status); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	return
}

func (tx *tx) Transmit(aud []Receiver, event *Event) error {
	t := jwt.New()
	t.Set(jwt.IssuerKey, tx.conf.Issuer)
	for _, r := range aud {
		t.Set(jwt.AudienceKey, r.Host)
	}
	t.Set(jwt.IssuedAtKey, time.Now())
	t.Set(jwt.JwtIDKey, "metyakutya-random")
	t.Set("events", event.ToClaim())

	ss, err := jwt.Sign(t, jwa.HS256, []byte("secret-hs-256-key"))
	if err != nil {
		return err
	}
	fmt.Printf("署名したよ %s\n", ss)
	for _, recv := range aud {
		req, err := http.NewRequest(http.MethodPost, recv.StreamConf.Delivery.URL, bytes.NewBuffer(ss))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/secevent+jwt")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("respons status code unmatched : %v", resp.Status)
		}
		fmt.Printf("送信に成功 recv: %v -> set: %s\n", recv, ss)
	}
	return nil
}

type TxError interface {
	error
	Code() TxErrorCode
	Option() interface{}
}

type TxErrorCode int

const (
	_ TxErrorCode = iota + 400
	// TxErrorUnAuthorized は 401 error
	// option として *http.Response が含まれるが、Body は読めない
	TxErrorUnAuthorized
	_
	_
	// TxErrorNotFound は 404 error
	TxErrorNotFound
)
