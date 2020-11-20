package cap

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/openid"
	"github.com/hatake5051/ztf-prototype/uma"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

func (c *Conf) New() *mux.Router {
	db := &db{}
	u := c.UMA.to().New()
	recvs := &recvs{
		"http://idp.ztf-proto.k3.ipv6.mobi/auth/realms/ztf-proto/protocol/openid-connect/certs",
		u,
		db,
	}
	tr := c.CAEP.to().New(recvs)
	for k, v := range c.CAEP.Receivers {
		db.SetReceiver(&caep.Receiver{
			ID:         k,
			Host:       v.Host,
			StreamConf: &caep.StreamConfig{},
		})
	}
	cap := &cap{
		ctxs:  c.CAP.Contexts,
		store: sessions.NewCookieStore([]byte("super-secret-key")),
		rp:    c.CAP.Openid.to().New(),
		uma:   u,
		db:    db,
	}
	r := mux.NewRouter()
	r.Use(cap.Log)
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/auth/list", http.StatusFound) })
	r.HandleFunc("/.well-known/sse-configuration", tr.WellKnown)
	sCAEP := r.PathPrefix("/set").Subrouter()
	sCAEP.PathPrefix("/stream").Methods("GET").HandlerFunc(tr.ReadStreamConfig)
	sCAEP.PathPrefix("/stream").Methods("POST").HandlerFunc(tr.UpdateStreamConfig)
	sCAEP.PathPrefix("/status/{spagID}").Methods("GET").HandlerFunc(tr.ReadStreamStatus)
	sCAEP.PathPrefix("/subject:add").Methods("POST").HandlerFunc(tr.AddSub)
	s := r.PathPrefix("/auth").Subrouter()
	r.PathPrefix("/oidc").Subrouter().HandleFunc("/callback", cap.OIDCCallback)
	s.Use(cap.OIDCMW)
	s.HandleFunc("/list", cap.CtxList)
	s.HandleFunc("/reg", cap.CtxReg)

	return r
}

type recvsDB interface {
	GetReceiver(RecvID string) (*caep.Receiver, error)
	SetReceiver(*caep.Receiver) (*caep.Receiver, error)
	GetSubStatus(RecvID, spagID string) (*caep.StreamStatus, error)
	SetSubStatus(RecvID string, status *caep.StreamStatus) (*caep.StreamStatus, error)
	GetContextID(sapgID, ctxID string) (resID string, err error)
	SetContextID(spagID, ctxID string, res *uma.Res) error
}

type db struct {
	m sync.Map
}

func (db *db) GetReceiver(recvID string) (*caep.Receiver, error) {
	v, ok := db.m.Load("recvid-" + recvID)
	if !ok {
		return nil, fmt.Errorf("対応するレシーバ情報がない %s", recvID)
	}
	return v.(*caep.Receiver), nil
}
func (db *db) SetReceiver(recv *caep.Receiver) (*caep.Receiver, error) {
	db.m.Store("recvid-"+recv.ID, recv)
	return recv, nil
}
func (db *db) GetSubStatus(recvID, spagID string) (*caep.StreamStatus, error) {
	v, ok := db.m.Load(recvID + "-status-" + spagID)
	if !ok {
		return nil, fmt.Errorf("対応するステータス情報がない recvID: %s spagID: %s", recvID, spagID)
	}
	return v.(*caep.StreamStatus), nil
}
func (db *db) SetSubStatus(recvID string, status *caep.StreamStatus) (*caep.StreamStatus, error) {
	db.m.Store(recvID+"-status-"+status.SpagID, status)
	return status, nil
}
func (db *db) GetContextID(spagID, ctxID string) (resID string, err error) {
	key := "spagid-" + spagID + "-ctxid-" + ctxID
	fmt.Printf("get context -> resource key: %s\n", key)
	v, ok := db.m.Load(key)
	if !ok {
		return "", fmt.Errorf("spagID: %s の ctxID: %s が見当たりません", spagID, ctxID)
	}
	res := v.(*uma.Res)
	return res.ID, nil
}

func (db *db) SetContextID(spagID, ctxID string, res *uma.Res) error {
	key := "spagid-" + spagID + "-ctxid-" + ctxID
	fmt.Printf("set context -> resource key: %s\n", key)
	db.m.Store(key, res)
	return nil
}

type recvs struct {
	jwtURL string
	uma    uma.ResSrv
	db     recvsDB
}

func (r *recvs) Verify(authHeader string) (*caep.Receiver, error) {
	hh := strings.Split(authHeader, " ")
	if len(hh) != 2 && hh[0] != "Bearer" {
		return nil, fmt.Errorf("authheader のフォーマットがおかしい %s", authHeader)
	}
	jwkset, err := jwk.FetchHTTP(r.jwtURL)
	if err != nil {
		return nil, err
	}
	tok, err := jwt.ParseString(hh[1], jwt.WithKeySet(jwkset))
	if err != nil {
		return nil, err
	}
	recvID, _ := tok.Get("azp")
	return r.db.GetReceiver(recvID.(string))
}

func (r *recvs) SubStatus(recv *caep.Receiver, spagID string) (*caep.StreamStatus, error) {
	return r.db.GetSubStatus(recv.ID, spagID)
}

func (r *recvs) SetSubStatus(recv *caep.Receiver, reqs *caep.ReqChangeOfStreamStatus) (*caep.StreamStatus, error) {
	return r.db.SetSubStatus(recv.ID, &reqs.StreamStatus)
}
func (r *recvs) SetStreamConf(recv *caep.Receiver, conf *caep.StreamConfig) (*caep.Receiver, error) {
	if ismodified := recv.StreamConf.Update(conf); ismodified {
		return r.db.SetReceiver(recv)
	}
	return recv, nil
}
func (r *recvs) SetSub(recv *caep.Receiver, status *caep.StreamStatus) error {
	if _, err := r.db.SetSubStatus(recv.ID, status); err != nil {
		return err
	}
	return nil
}

func (r *recvs) VerifyAndValidateAddSub(authHeader string, req *caep.ReqAddSub) (*caep.Receiver, *caep.StreamStatus, error) {
	hh := strings.Split(authHeader, " ")
	spagID := req.Sub.SpagID
	if len(hh) != 2 && hh[0] != "Bearer" {
		// RPT トークンがないということは .. ?
		var reses []uma.ResReqForPT
		for ctxID, scopes := range req.ReqEventScopes {
			resID, err := r.db.GetContextID(spagID, ctxID)
			if err != nil {
				continue
			}
			res := uma.ResReqForPT{
				ID:     resID,
				Scopes: scopes,
			}
			reses = append(reses, res)
		}
		if len(reses) == 0 {
			return nil, nil, newTrE(fmt.Errorf("this sub(id: %s) ", spagID), caep.TransErrorNotFound)
		}
		pt, err := r.uma.PermissionTicket(reses)
		if err != nil {
			return nil, nil, err
		}
		s := fmt.Sprintf(`UMA realm="%s",as_uri="%s",ticket="%s"`, pt.InitialOption.ResSrv, pt.InitialOption.AuthZSrv, pt.Ticket)
		m := map[string]string{"WWW-Authenticate": s}
		return nil, nil, newTrEO(fmt.Errorf("UMA NoRPT"), caep.TransErrorUnAuthorized, m)
	}
	jwkset, err := jwk.FetchHTTP(r.jwtURL)
	if err != nil {
		return nil, nil, err
	}
	tok, err := jwt.ParseString(hh[1], jwt.WithKeySet(jwkset))
	if err != nil {
		return nil, nil, err
	}

	recvID, _ := tok.Get("azp")
	recv, err := r.db.GetReceiver(recvID.(string))
	if err != nil {
		return nil, nil, err
	}

	eventscopes := make(map[string][]string)
	v, ok := tok.Get("authorization")
	if !ok {
		return nil, nil, fmt.Errorf("RPTパースえらー")
	}
	v1, ok := v.(map[string]interface{})
	v2, ok := v1["permissions"]
	v3, ok := v2.([]interface{})
	for _, v4 := range v3 {
		v5, ok := v4.(map[string]interface{})
		if !ok {
			return nil, nil, fmt.Errorf("RPTパースえらー")
		}
		v6, ok := v5["scopes"]
		fmt.Printf("v6 %#v\n", v6)
		v7, ok := v6.([]interface{})
		var scopes []string
		for _, v8 := range v7 {
			s, ok := v8.(string)
			if !ok {
				return nil, nil, fmt.Errorf("RPTパースえらー")
			}
			scopes = append(scopes, s)
		}
		v9, ok := v5["rsname"]
		ctxID, ok := v9.(string)
		eventscopes[ctxID] = scopes
	}
	status := &caep.StreamStatus{"enabled", spagID, eventscopes}
	return recv, status, nil
}

func newTrE(err error, code caep.TransErrorCode) caep.TransError {
	return &tre{err, code, nil}
}

func newTrEO(err error, code caep.TransErrorCode, opt interface{}) caep.TransError {
	return &tre{err, code, opt}
}

type tre struct {
	error
	code caep.TransErrorCode
	opt  interface{}
}

func (e *tre) Code() caep.TransErrorCode {
	return e.code
}

func (e *tre) Option() interface{} {
	return e.opt
}

type cap struct {
	ctxs  map[string][]string
	store *sessions.CookieStore
	rp    openid.RP
	db    recvsDB
	uma   uma.ResSrv
}

func (c *cap) CtxList(w http.ResponseWriter, r *http.Request) {
	session, err := c.store.Get(r, "cookie-auth")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sub, ok := session.Values["subject"].(string)
	name, ok := session.Values["name"].(string)
	if !ok {
		http.Error(w, "認証MWを潜り抜けている！！", http.StatusForbidden)
		return
	}
	reses, err := c.uma.List(sub)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s := fmt.Sprintf("<html><head/><body><h1>%sさん、こんにちは</h1>", name)
	s += "<h1>コンテキスト一覧</h1>"
	s += "<ul>"
	for ctxID, _ := range c.ctxs {
		isContained := false
		if resID, err := c.db.GetContextID(sub, ctxID); err == nil {
			for _, rr := range reses {
				if rr == resID {
					isContained = true
					break
				}
			}
		}
		s += fmt.Sprintf("<li>ctx(%s)は認可サーバで保護", ctxID)
		if isContained {
			s += "されています"
		} else {
			s += fmt.Sprintf(`されていません、 <a href="/auth/reg?id=%s"> 保護する</a>`, ctxID)
		}
		s += "</li>"
	}
	s += "</ul></body></html>"
	// んー、<> をエスケープしない
	w.Write([]byte(s))
}

func (c *cap) CtxReg(w http.ResponseWriter, r *http.Request) {
	session, err := c.store.Get(r, "cookie-auth")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sub, ok := session.Values["subject"].(string)
	_, ok = session.Values["name"].(string)
	if !ok {
		http.Error(w, "認証MWを潜り抜けている！！", http.StatusForbidden)
		return
	}
	ctxID := r.URL.Query().Get("id")
	var res *uma.Res
	for k, v := range c.ctxs {
		if k == ctxID {
			res = &uma.Res{
				Name:   k,
				Owner:  sub,
				Scopes: v,
			}
			break
		}
	}
	if res == nil {
		http.Error(w, "クエリが正しくないよ", http.StatusBadRequest)
		return
	}
	res, err = c.uma.CRUD("POST", res)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c.db.SetContextID(sub, res.Name, res)
	s := "<html><head/><body><h1>コンテキスト一覧</h1>"
	s += "<ul>"
	s += "<li>ID: " + res.ID + "</li>"
	s += "<li>Name: " + res.Name + "</li>"
	s += "<li>Owner: " + res.Owner + "</li>"
	s += fmt.Sprintf("<li>%s: %t</li>", "OwnerManagedAccess", res.OwnerManagedAccess)
	s += fmt.Sprintf("<li>%s: %s</li>", "Scopes", strings.Join(res.Scopes, " "))
	s += "</ul></body></html>"
	// んー、<> をエスケープしない
	w.Write([]byte(s))
}

func (c *cap) Log(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("r is %v\n", r)
		next.ServeHTTP(w, r)
	})
}

func (c *cap) OIDCMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/callback" {
			next.ServeHTTP(w, r)
			return
		}
		session, err := c.store.Get(r, "cookie-auth")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, ok := session.Values["subject"].(string)
		if !ok {
			session.Values["return-address"] = r.URL.String()
			session.Save(r, w)
			c.rp.Redirect(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (c *cap) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	idToken, err := c.rp.CallbackAndExchange(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session, err := c.store.Get(r, "cookie-auth")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("%#v\n", idToken)
	session.Values["subject"] = idToken.Subject()
	session.Values["name"] = idToken.PreferredUsername()
	if err := session.Save(r, w); err != nil {
		log.Printf("error %#v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ret, ok := session.Values["return-address"].(string)
	if !ok {
		http.Error(w, "return-address missing", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, ret, http.StatusFound)
}
