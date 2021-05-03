package cap

import (
	"fmt"
	"strings"
	"sync"

	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/uma"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

type verifier struct {
	jwtURL string
}

func (v *verifier) Stream(authHeader string) (recvID string, err error) {
	hh := strings.Split(authHeader, " ")
	if len(hh) != 2 && hh[0] != "Bearer" {
		return "", fmt.Errorf("authheader のフォーマットがおかしい %s", authHeader)
	}
	jwkset, err := jwk.FetchHTTP(v.jwtURL)
	if err != nil {
		return "", err
	}
	tok, err := jwt.ParseString(hh[1], jwt.WithKeySet(jwkset))
	if err != nil {
		return "", err
	}
	vv, _ := tok.Get("azp")
	return vv.(string), nil
}

func (v *verifier) Status(authHeader string, req *caep.ReqChangeOfStreamStatus) (recvID string, status *caep.StreamStatus, err error) {
	hh := strings.Split(authHeader, " ")
	if len(hh) != 2 && hh[0] != "Bearer" {
		return "", nil, fmt.Errorf("authheader のフォーマットがおかしい %s", authHeader)
	}
	jwkset, err := jwk.FetchHTTP(v.jwtURL)
	if err != nil {
		return "", nil, err
	}
	tok, err := jwt.ParseString(hh[1], jwt.WithKeySet(jwkset))
	if err != nil {
		return "", nil, err
	}
	vv, _ := tok.Get("azp")
	recvID = vv.(string)

	if req != nil {
		// TODO: req の認可チェック
		return recvID, &req.StreamStatus, nil
	}
	return recvID, nil, nil
}

type addsubverifier struct {
	verifier
	uma uma.ResSrv
	db  CtxDBForUMAResSrv
}

func (v *addsubverifier) AddSub(authHeader string, req *caep.ReqAddSub) (recvID string, status *caep.StreamStatus, err error) {
	hh := strings.Split(authHeader, " ")
	spagID := req.Sub.SpagID
	if len(hh) != 2 && hh[0] != "Bearer" {
		// RPT トークンがないということは .. ?
		var reqs []uma.ResReqForPT
		for ctxID, scopes := range req.ReqEventScopes {
			res, err := v.db.Load(SubAtCAP(spagID), ctxType(ctxID))
			if err != nil {
				continue
			}
			req := uma.ResReqForPT{
				ID:     res.IDAtAuthZSrv,
				Scopes: scopes,
			}
			reqs = append(reqs, req)
		}
		if len(reqs) == 0 {
			return "", nil, newTrE(fmt.Errorf("this sub(id: %s) は一つもコンテキストをCAEPの対象としていない", spagID), caep.TransErrorNotFound)
		}
		pt, err := v.uma.PermissionTicket(reqs)
		if err != nil {
			return "", nil, err
		}
		s := fmt.Sprintf(`UMA realm="%s",as_uri="%s",ticket="%s"`, pt.InitialOption.ResSrv, pt.InitialOption.AuthZSrv, pt.Ticket)
		m := map[string]string{"WWW-Authenticate": s}
		return "", nil, newTrEO(fmt.Errorf("UMA NoRPT"), caep.TransErrorUnAuthorized, m)
	}
	jwkset, err := jwk.FetchHTTP(v.jwtURL)
	if err != nil {
		return "", nil, err
	}
	tok, err := jwt.ParseString(hh[1], jwt.WithKeySet(jwkset))
	if err != nil {
		return "", nil, err
	}

	vv, _ := tok.Get("azp")
	recvID = vv.(string)
	eventscopes, err := permittedEventScopesFrom(tok)
	if err != nil {
		return "", nil, err
	}
	status = &caep.StreamStatus{
		Status:      "enabled",
		SpagID:      spagID,
		EventScopes: eventscopes,
	}
	return recvID, status, nil
}

func permittedEventScopesFrom(tok jwt.Token) (map[string][]string, error) {
	eventscopes := make(map[string][]string)
	vv, ok := tok.Get("authorization")
	if !ok {
		return nil, fmt.Errorf("RPTパースえらー")
	}
	v1, ok := vv.(map[string]interface{})
	v2, ok := v1["permissions"]
	v3, ok := v2.([]interface{})
	for _, v4 := range v3 {
		v5, ok := v4.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("RPTパースえらー")
		}
		v6, ok := v5["scopes"]
		v7, ok := v6.([]interface{})
		var scopes []string
		for _, v8 := range v7 {
			s, ok := v8.(string)
			if !ok {
				return nil, fmt.Errorf("RPTパースえらー")
			}
			scopes = append(scopes, s)
		}
		v9, ok := v5["rsname"]
		ctxID, ok := v9.(string)
		eventscopes[ctxID] = scopes
	}
	return eventscopes, nil
}

type trStreamDB struct {
	m  sync.RWMutex
	db map[string]caep.Receiver
}

func (db *trStreamDB) Load(recvID string) (*caep.Receiver, error) {
	db.m.RLock()
	defer db.m.RUnlock()
	recv, ok := db.db[recvID]
	if !ok {
		return nil, fmt.Errorf("recvID(%s) は登録されてません", recvID)
	}
	return &recv, nil
}

func (db *trStreamDB) Save(recv *caep.Receiver) error {
	db.m.Lock()
	defer db.m.Unlock()
	db.db[recv.ID] = *recv
	return nil
}

type trStatusDB struct {
	m  sync.RWMutex
	db map[string]map[string]caep.StreamStatus
}

func (db *trStatusDB) Load(recvID, spagID string) (*caep.StreamStatus, error) {
	db.m.RLock()
	defer db.m.RUnlock()
	subs, ok := db.db[recvID]
	if !ok || subs == nil {
		return nil, fmt.Errorf("recvID(%s) にはまだ status が一つもない", recvID)
	}
	status, ok := subs[spagID]
	if !ok {
		return nil, fmt.Errorf("recvID(%s) には spagID(%s) のステータスがない", recvID, spagID)
	}
	return &status, nil
}

func (db *trStatusDB) Save(recvID string, status *caep.StreamStatus) error {
	db.m.Lock()
	defer db.m.Unlock()
	subs, ok := db.db[recvID]
	if !ok || subs == nil {
		subs = make(map[string]caep.StreamStatus)
		db.db[recvID] = subs
	}
	subs[status.SpagID] = *status
	return nil
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
