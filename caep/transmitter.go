package caep

import (
	"bytes"
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
type TransConf struct {
	Tr *Transmitter
}

func (c *TransConf) New(recvs Recvs) Tr {
	return &tr{
		conf:  c.Tr,
		recvs: recvs,
	}
}

type Tr interface {
	WellKnown(w http.ResponseWriter, r *http.Request)
	ReadStreamStatus(w http.ResponseWriter, r *http.Request)
	UpdateStreamStatus(w http.ResponseWriter, r *http.Request)
	ReadStreamConfig(w http.ResponseWriter, r *http.Request)
	UpdateStreamConfig(w http.ResponseWriter, r *http.Request)
	AddSub(w http.ResponseWriter, r *http.Request)
	Transmit(aud []Receiver, event *SSEEventClaim) error
}

type Recvs interface {
	Verify(authHeader string) (*Receiver, error)
	VerifyAndValidateAddSub(authHeader string, req *ReqAddSub) (*Receiver, *StreamStatus, error)
	SubStatus(recv *Receiver, spgID string) (*StreamStatus, error)
	SetSubStatus(*Receiver, *ReqChangeOfStreamStatus) (*StreamStatus, error)
	SetStreamConf(*Receiver, *StreamConfig) (*Receiver, error)
	SetSub(*Receiver, *StreamStatus) error
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
	conf  *Transmitter
	recvs Recvs
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
	recv, err := tr.recvs.Verify(r.Header.Get("Authorization"))
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
	spagID := mux.Vars(r)["spagID"]
	j, err := tr.recvs.SubStatus(recv, spagID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(j); err != nil {
		http.Error(w, "失敗", http.StatusInternalServerError)
		return
	}
}

func (tr *tr) UpdateStreamStatus(w http.ResponseWriter, r *http.Request) {
	// Token の検証をして、対応する Receiver を識別する (Sec.9)
	recv, err := tr.recvs.Verify(r.Header.Get("Authorization"))
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
	defer r.Body.Close()
	reqStatus := new(ReqChangeOfStreamStatus)
	if err := json.NewDecoder(r.Body).Decode(reqStatus); err != nil {
		http.Error(w, "status update 要求のパースに失敗", http.StatusNotFound)
		return
	}
	j, err := tr.recvs.SetSubStatus(recv, reqStatus)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(j); err != nil {
		http.Error(w, "失敗", http.StatusInternalServerError)
		return
	}
}

func (tr *tr) ReadStreamConfig(w http.ResponseWriter, r *http.Request) {
	// Token の検証をして、対応する Receiver を識別する (Sec.9)
	recv, err := tr.recvs.Verify(r.Header.Get("Authorization"))
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
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(recv.StreamConf); err != nil {
		http.Error(w, "失敗", http.StatusInternalServerError)
		return
	}
}

func (tr *tr) UpdateStreamConfig(w http.ResponseWriter, r *http.Request) {
	// Token の検証をして、対応する Receiver を識別する (Sec.9)
	recv, err := tr.recvs.Verify(r.Header.Get("Authorization"))
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
	defer r.Body.Close()
	req := new(StreamConfig)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		http.Error(w, "status update 要求のパースに失敗", http.StatusNotFound)
		return
	}
	recv, err = tr.recvs.SetStreamConf(recv, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(recv.StreamConf); err != nil {
		http.Error(w, "失敗", http.StatusInternalServerError)
		return
	}
}

func (tr *tr) AddSub(w http.ResponseWriter, r *http.Request) {
	// 要求をパースする
	defer r.Body.Close()
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
	recv, status, err := tr.recvs.VerifyAndValidateAddSub(r.Header.Get("Authorization"), req)
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
	if err := tr.recvs.SetSub(recv, status); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	return
	// //
	// rpt := r.Header.Get("Authorization")
	// if rpt != "" { // TODO rpt validate
	// 	fmt.Printf("subject(%v)を追加しました\nrpt: %s\n", addSubReq, rpt)
	// 	tr.subjects.Store(addSubReq.Sub.SpagID, rpt)
	// 	if err := tr.Transmit(addSubReq.Sub.SpagID, &Context{
	// 		Issuer: tr.Host,
	// 		ID:     "ctx1",
	// 		ScopeValues: map[string]string{
	// 			"scope1": "scope1-value",
	// 			"scope2": "scope2-value",
	// 		},
	// 	}); err != nil {
	// 		fmt.Printf("送信に失敗したらしい %v", err)
	// 	}
	// 	return
	// }
	// var reqreses []uma.ResReqForPT
	// ctxIDMap := map[string]string{
	// 	"ctx1": "49f536eb-41ce-4084-9389-0aae1c8b95c8",
	// 	"ctx2": "8353208d-376e-4c40-a1a7-af6cd84f6522",
	// }
	// for id, scopes := range addSubReq.ReqCtx {
	// 	u := uma.ResReqForPT{
	// 		ID:     ctxIDMap[id],
	// 		Scopes: scopes,
	// 	}
	// 	reqreses = append(reqreses, u)
	// }
	// pt, err := tr.uma.PermissionTicket(reqreses)
	// if err != nil {
	// 	fmt.Printf("チケットの取得に失敗... %v", err)
	// 	http.Error(w, fmt.Sprintf("チケットの取得に失敗 %v", err), http.StatusInternalServerError)
	// 	return
	// }
	// s := fmt.Sprintf(`UMA realm="%s",as_uri="%s",ticket="%s"`, pt.InitialOption.ResSrv, pt.InitialOption.AuthZSrv, pt.Ticket)
	// w.Header().Add("WWW-Authenticate", s)
	// w.WriteHeader(http.StatusUnauthorized)
}

func (tr *tr) Transmit(aud []Receiver, event *SSEEventClaim) error {
	t := jwt.New()
	t.Set(jwt.IssuerKey, tr.conf.Issuer)
	for _, r := range aud {
		t.Set(jwt.AudienceKey, r.Host)
	}
	t.Set(jwt.IssuedAtKey, time.Now())
	t.Set(jwt.JwtIDKey, "metyakutya-random")
	t.Set("events", event.toClaim())

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
