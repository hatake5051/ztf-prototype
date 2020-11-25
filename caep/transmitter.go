package caep

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
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

// New は設定情報から caep の transmitter を構築する
func (c *TransConf) New(recvRepo RecvRepo, subStatusRepo SubStatusRepo, verifier Verifier) Tr {
	return &tr{
		conf:       c.Tr,
		recvRepo:   recvRepo,
		statusRepo: subStatusRepo,
		verifier:   verifier,
	}
}

// Tr は CAEP の Transmitter を表す
type Tr interface {
	// Router は CAEP Transmitter Endpoint を mux.Router に構築する
	Router(r *mux.Router)
	// Transmit は aud に event を送信する
	Transmit(aud []Receiver, event *SSEEventClaim) error
}

// RecvRepo は Transmitter が管轄している Receiver を永続化する
type RecvRepo interface {
	Load(recvID string) (*Receiver, error)
	Save(*Receiver) error
}

// SubStatusRepo は Transmitter が管轄している Receiver のサブジェクトごとの status を永続化する
type SubStatusRepo interface {
	Load(recvID, spagID string) (*StreamStatus, error)
	Save(recvID string, status *StreamStatus) error
}

// Verifier は Receiver が Event Stream Management API を叩く時の認可情報を検証する
// また、認可情報から recveiver を識別する
// Status のときは ReqChangeOfStreamStatus の認可情報を見てそれに基づいて更新した status を返す
// AddSub のときは ReqAddSub を authHeader の認可情報を見てそれに基づいて更新した status を返す
type Verifier interface {
	Stream(authHeader string) (recvID string, err error)
	Status(authHeader string, req *ReqChangeOfStreamStatus) (recvID string, status *StreamStatus, err error)
	AddSub(authHeader string, req *ReqAddSub) (recvID string, status *StreamStatus, err error)
}

type TransError interface {
	error
	Code() TransErrorCode
	Option() interface{}
}

type TransErrorCode int

const (
	_ TransErrorCode = iota + 400
	// TransErrorUnAuthorized は 401 error
	// option として *http.Response が含まれるが、Body は読めない
	TransErrorUnAuthorized
	_
	_
	// TransErrorNotFound は 404 error
	TransErrorNotFound
)

type tr struct {
	conf       *Transmitter
	recvRepo   RecvRepo
	statusRepo SubStatusRepo
	verifier   Verifier
}

func (tr *tr) Router(r *mux.Router) {
	r.HandleFunc("/.well-known/sse-configuration", tr.WellKnown)
	u, err := url.Parse(tr.conf.ConfigurationEndpoint)
	if err != nil {
		panic("設定をミスってるよ" + err.Error())
	}
	r.PathPrefix(u.Path).Methods("GET").HandlerFunc(tr.ReadStreamConfig)
	r.PathPrefix(u.Path).Methods("POST").HandlerFunc(tr.UpdateStreamConfig)
	u, err = url.Parse(tr.conf.StatusEndpoint)
	if err != nil {
		panic("設定をミスってるよ" + err.Error())
	}
	r.PathPrefix(u.Path + "/{spag}").Methods("GET").HandlerFunc(tr.ReadStreamStatus)
	u, err = url.Parse(tr.conf.AddSubjectEndpoint)
	if err != nil {
		panic("設定をミスってるよ" + err.Error())
	}
	r.PathPrefix(u.Path).Methods("POST").HandlerFunc(tr.AddSub)
}

func (tr *tr) WellKnown(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := tr.conf.Write(w); err != nil {
		http.Error(w, "失敗", http.StatusInternalServerError)
		return
	}
}

func (tr *tr) ReadStreamStatus(w http.ResponseWriter, r *http.Request) {
	// Token の検証をして、対応する Receiver を識別する (Sec.9)
	recvID, _, err := tr.verifier.Status(r.Header.Get("Authorization"), nil)
	if err != nil {
		if err, ok := err.(TransError); ok {
			if err.Code() == TransErrorUnAuthorized {
				headers := err.Option().(map[string]string)
				for k, v := range headers {
					w.Header().Set(k, v)
				}
			}
		}
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// spagID の status を調べようとしているかチェック
	spagID := mux.Vars(r)["spag"]
	status, err := tr.statusRepo.Load(recvID, spagID)
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

func (tr *tr) UpdateStreamStatus(w http.ResponseWriter, r *http.Request) {
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
	recvID, status, err := tr.verifier.Status(r.Header.Get("Authorization"), reqStatus)
	if err != nil {
		if err, ok := err.(TransError); ok {
			if err.Code() == TransErrorUnAuthorized {
				headers := err.Option().(map[string]string)
				for k, v := range headers {
					w.Header().Set(k, v)
				}
			}
		}
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := tr.statusRepo.Save(recvID, status); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (tr *tr) ReadStreamConfig(w http.ResponseWriter, r *http.Request) {
	// Token の検証をして、対応する Receiver を識別する (Sec.9)
	recvID, err := tr.verifier.Stream(r.Header.Get("Authorization"))
	if err != nil {
		if err, ok := err.(TransError); ok {
			if err.Code() == TransErrorUnAuthorized {
				headers := err.Option().(map[string]string)
				for k, v := range headers {
					w.Header().Set(k, v)
				}
			}
		}
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	recv, err := tr.recvRepo.Load(recvID)
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

func (tr *tr) UpdateStreamConfig(w http.ResponseWriter, r *http.Request) {
	// Token の検証をして、対応する Receiver を識別する (Sec.9)
	recvID, err := tr.verifier.Stream(r.Header.Get("Authorization"))
	if err != nil {
		if err, ok := err.(TransError); ok {
			if err.Code() == TransErrorUnAuthorized {
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
	recv, err := tr.recvRepo.Load(recvID)
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
		if err := tr.recvRepo.Save(recv); err != nil {
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

func (tr *tr) AddSub(w http.ResponseWriter, r *http.Request) {
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
	recvID, status, err := tr.verifier.AddSub(r.Header.Get("Authorization"), req)
	if err != nil {
		if err, ok := err.(TransError); ok {
			if err.Code() == TransErrorUnAuthorized {
				headers := err.Option().(map[string]string)
				for k, v := range headers {
					w.Header().Set(k, v)
				}
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			if err.Code() == TransErrorNotFound {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
		}
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := tr.statusRepo.Save(recvID, status); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	return
}

func (tr *tr) Transmit(aud []Receiver, event *SSEEventClaim) error {
	t := jwt.New()
	t.Set(jwt.IssuerKey, tr.conf.Issuer)
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
