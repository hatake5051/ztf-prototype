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

var _ caep.Verifier = &addsubverifier{}

// addsubverifier は caep.verifier を満たす
type addsubverifier struct {
	verifier
	uma uma.ResSrv
	pid SubPIDTranslater
}

func (v *addsubverifier) AddSub(authHeader string, req *caep.ReqAddSub) (caep.RxID, *caep.StreamStatus, error) {
	tok, err := v.verifyHeader(authHeader)
	if err != nil {
		// RPT トークンがない -> UMA Grant Flow を始める
		var reqs []uma.ResReqForPT
		for _, opts := range req.ReqEventScopes {
			var ss []string
			for _, s := range opts.Scopes {
				ss = append(ss, string(s))
			}
			req := uma.ResReqForPT{
				ID:     uma.ResID(opts.EventID),
				Scopes: ss,
			}
			reqs = append(reqs, req)
		}
		pt, err := v.uma.PermissionTicket(reqs)
		if err != nil {
			return "", nil, err
		}
		s := fmt.Sprintf(`UMA realm="%s",as_uri="%s",ticket="%s"`, pt.InitialOption.ResSrv, pt.InitialOption.AuthZSrv, pt.Ticket)
		m := map[string]string{"WWW-Authenticate": s}
		return caep.RxID(""), nil, newTrEO(fmt.Errorf("UMA NoRPT"), caep.TxErrorUnAuthorized, m)
	}
	rxID, ok := extractRxIDFromToken(tok)
	if !ok {
		return caep.RxID(""), nil, fmt.Errorf("RxID を RPT から取得できなかった %#v", tok)
	}
	for _, opt := range req.ReqEventScopes {
		if err := v.pid.BindResIDToPID(uma.ResID(opt.EventID), rxID, req.Subject); err != nil {
			return rxID, nil, fmt.Errorf("uma.ResID と PID の紐付けに失敗" + err.Error())
		}
	}
	eventscopes, err := permittedEventScopesFromToken(tok)
	if err != nil {
		return rxID, nil, err
	}
	status := &caep.StreamStatus{
		Status:      "enabled",
		Subject:     *req.Subject,
		EventScopes: eventscopes,
	}
	return rxID, status, nil
}

// verifier は caep.Verifier のうち、 Stream と Status を実装する
type verifier struct {
	jwtURL string
}

func (v *verifier) Stream(authHeader string) (caep.RxID, error) {
	tok, err := v.verifyHeader(authHeader)
	if err != nil {
		return caep.RxID(""), err
	}
	rxID, ok := extractRxIDFromToken(tok)
	if !ok {
		return caep.RxID(""), fmt.Errorf("Token から ReceiverID を取得できなかった")
	}
	return rxID, nil
}

func (v *verifier) Status(authHeader string, req *caep.ReqChangeOfStreamStatus) (caep.RxID, *caep.StreamStatus, error) {
	tok, err := v.verifyHeader(authHeader)
	if err != nil {
		return caep.RxID(""), nil, err
	}
	rxID, ok := extractRxIDFromToken(tok)
	if !ok {
		return caep.RxID(""), nil, fmt.Errorf("Receive iD を取得できなかった")
	}
	if req != nil {
		// TODO: req の認可チェック
		return rxID, &req.StreamStatus, nil
	}
	return rxID, nil, nil
}

func (v *verifier) verifyHeader(authHeader string) (jwt.Token, error) {
	// authHeader は "Bearer <Token>" の形
	hh := strings.Split(authHeader, " ")
	if len(hh) != 2 && hh[0] != "Bearer" {
		return nil, fmt.Errorf("authheader のフォーマットがおかしい %s", authHeader)
	}
	// Token の検証を行う
	jwkset, err := jwk.FetchHTTP(v.jwtURL)
	if err != nil {
		return nil, err
	}
	return jwt.ParseString(hh[1], jwt.WithKeySet(jwkset))
}

func extractRxIDFromToken(tok jwt.Token) (rxID caep.RxID, ok bool) {
	// AuthoriZed Party にクライアント情報がある
	azp, ok := tok.Get("azp")
	if !ok {
		return rxID, ok
	}
	azpStr, ok := azp.(string)
	if !ok {
		return rxID, ok
	}
	return caep.RxID(azpStr), true
}

func permittedEventScopesFromToken(tok jwt.Token) (map[caep.EventType][]caep.EventScope, error) {
	eventscopes := make(map[caep.EventType][]caep.EventScope)
	az, ok := tok.Get("authorization")
	if !ok {
		return nil, fmt.Errorf("RPTパースえらー")
	}
	v1, ok := az.(map[string]interface{})
	v2, ok := v1["permissions"]
	v3, ok := v2.([]interface{})
	for _, v4 := range v3 {
		v5, ok := v4.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("RPTパースえらー")
		}
		v6, ok := v5["scopes"]
		v7, ok := v6.([]interface{})
		var scopes []caep.EventScope
		for _, v8 := range v7 {
			s, ok := v8.(string)
			if !ok {
				return nil, fmt.Errorf("RPTパースえらー")
			}
			scopes = append(scopes, caep.EventScope(s))
		}
		v9, ok := v5["rsname"]
		ct, ok := v9.(string)
		eventscopes[caep.EventType(string(ct))] = scopes
	}
	return eventscopes, nil
}

// trStreamDB は Transmitter の Receiver 情報を保存するデータベース
type trStreamDB struct {
	m  sync.RWMutex
	db map[caep.RxID]caep.Receiver
}

var _ caep.RxRepo = &trStreamDB{}

func (db *trStreamDB) Load(recvID caep.RxID) (*caep.Receiver, error) {
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
	db map[caep.RxID]map[string]caep.StreamStatus
}

var _ caep.SubStatusRepo = &trStatusDB{}

func (db *trStatusDB) Load(rxID caep.RxID, sub *caep.EventSubject) (*caep.StreamStatus, error) {
	db.m.RLock()
	defer db.m.RUnlock()
	subs, ok := db.db[rxID]
	if !ok || subs == nil {
		return nil, fmt.Errorf("recvID(%s) にはまだ status が一つもない", rxID)
	}
	status, ok := subs[sub.Identifier()]
	if !ok {
		return nil, fmt.Errorf("recvID(%s) には spagID(%v) のステータスがない", rxID, sub)
	}
	return &status, nil
}

func (db *trStatusDB) Save(rxID caep.RxID, status *caep.StreamStatus) error {
	db.m.Lock()
	defer db.m.Unlock()
	subs, ok := db.db[rxID]
	if !ok || subs == nil {
		subs = make(map[string]caep.StreamStatus)
		db.db[rxID] = subs
	}
	subs[status.Subject.Identifier()] = *status
	return nil
}

func newTrE(err error, code caep.TxErrorCode) caep.TxError {
	return &tre{err, code, nil}
}

func newTrEO(err error, code caep.TxErrorCode, opt interface{}) caep.TxError {
	return &tre{err, code, opt}
}

type tre struct {
	error
	code caep.TxErrorCode
	opt  interface{}
}

func (e *tre) Code() caep.TxErrorCode {
	return e.code
}

func (e *tre) Option() interface{} {
	return e.opt
}
