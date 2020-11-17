package caep

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"sync"

	"github.com/gorilla/mux"
	"github.com/hatake5051/ztf-prototype/uma"
)

type Conf struct {
	Host string
}

func (c *Conf) New(uma uma.ResSrv) Tr {
	return &tr{Host: c.Host, uma: uma}
}

type Tr interface {
	WellKnown(w http.ResponseWriter, r *http.Request)
	GetCtxStreamConfig(w http.ResponseWriter, r *http.Request)
	GetStreamStatus(w http.ResponseWriter, r *http.Request)
	AddSub(w http.ResponseWriter, r *http.Request)
}

type tr struct {
	Host     string
	subjects sync.Map
	uma      uma.ResSrv
}

func (tr *tr) WellKnown(w http.ResponseWriter, r *http.Request) {
	j := &transmitterJSON{
		Issuer:                tr.Host,
		ConfigurationEndpoint: tr.Host + "/set/stream",
		StatusEndpoint:        tr.Host + "/set/status",
		AddSubjectEndpoint:    tr.Host + "/set/subject:add",
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(j); err != nil {
		http.Error(w, "失敗", http.StatusInternalServerError)
		return
	}
	return
}

func (tr *tr) GetCtxStreamConfig(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("ctx stream get with authorization: %s\n", r.Header.Get("Authorization"))
	j := &CtxStreamConfig{
		Iss: "http://localhost:9090",
		Aud: []string{"http://localhost:8080"},
		Delivery: struct {
			DeliveryMethod string `json:"delivery_method"`
			URL            string `json:"url"`
		}{
			DeliveryMethod: "https://schemas.openid.net/secevent/risc/delivery-method/push",
			URL:            "http://localhost:8080/pip/ctx/recv"},
		EventsSupported: []string{"ctx1", "ctx2"},
		EventsRequested: []string{"ctx1", "ctx2"},
		EventsDelivered: []string{"ctx1", "ctx2"},
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(j); err != nil {
		http.Error(w, "失敗", http.StatusInternalServerError)
		return
	}
	return
}

func (tr *tr) GetStreamStatus(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("get stream status\n")
	spagID := mux.Vars(r)["spagID"]
	j := &CtxStreamStatus{SpagID: spagID}
	_, ok := tr.subjects.Load(spagID)
	if !ok {
		j.Status = "none"
	} else {
		j.Status = "enabled"
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(j); err != nil {
		http.Error(w, "失敗", http.StatusInternalServerError)
		return
	}
	return
}

func (tr *tr) AddSub(w http.ResponseWriter, r *http.Request) {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if contentType != "application/json" {
		http.Error(w, "unmached content-type", http.StatusBadRequest)
		return
	}
	var addSubReq AddSubReq
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&addSubReq); err != nil {
		http.Error(w, fmt.Sprintf("フォーマットに失敗 %v", err), http.StatusBadRequest)
		return
	}
	rpt := r.Header.Get("Authorization")
	if rpt != "" { // TODO rpt validate
		fmt.Printf("subject(%v)を追加しました\n", addSubReq)
		tr.subjects.Store(addSubReq.Sub.SpagID, "ok")
		w.WriteHeader(200)
		return
	}
	var reqreses []uma.ResReqForPT
	ctxIDMap := map[string]string{
		"ctx1": "49f536eb-41ce-4084-9389-0aae1c8b95c8",
		"ctx2": "8353208d-376e-4c40-a1a7-af6cd84f6522",
	}
	for id, scopes := range addSubReq.ReqCtx {
		u := uma.ResReqForPT{
			ID:     ctxIDMap[id],
			Scopes: scopes,
		}
		reqreses = append(reqreses, u)
	}
	pt, err := tr.uma.PermissionTicket(reqreses)
	if err != nil {
		fmt.Printf("チケットの取得に失敗... %v", err)
		http.Error(w, fmt.Sprintf("チケットの取得に失敗 %v", err), http.StatusInternalServerError)
		return
	}
	s := fmt.Sprintf(`UMA realm="%s",as_uri="%s",ticket="%s"`, pt.InitialOption.ResSrv, pt.InitialOption.AuthZSrv, pt.Ticket)
	w.Header().Add("WWW-Authenticate", s)
	w.WriteHeader(http.StatusUnauthorized)
}
