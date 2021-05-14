package tx

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/ctx"
	"github.com/lestrrat-go/jwx/jwt"
)

func (conf *CAEPConf) new(eventsupported []string, u *umaResSrv, notification func(ctx.Sub, []ctx.Type) error, trans TranslaterForCAEP) *caepTx {
	rxs := &rxDB{trans, notification, sync.RWMutex{}, make(map[caep.RxID]*caep.StreamConfig), make(map[caep.RxID]map[string]struct {
		status     *caep.StreamStatus
		expiration time.Time
	}), make(map[string]map[caep.RxID]bool)}

	for rxID, rx := range conf.Receivers {
		if err := rxs.SaveStream(caep.RxID(rxID), &caep.StreamConfig{
			Iss:             conf.Metadata.Issuer,
			Aud:             rx.Host,
			EventsSupported: eventsupported,
		}); err != nil {
			panic("rxDB の構築に失敗" + err.Error())
		}
	}
	v := &verifier{u, rxs, trans}
	return &caepTx{conf.to().New(rxs, rxs, v), rxs, trans}
}

type caepTx struct {
	caep  caep.Tx
	rxDB  *rxDB
	trans TranslaterForCAEP
}

func (tx *caepTx) Transmit(context context.Context, c ctx.Ctx) error {
	auds := tx.rxDB.auds(c.Type())
	et := tx.trans.EventType(c.Type())
	for aud := range auds {
		esub, err := tx.trans.EventSubject(c.ID(), aud)
		if err != nil {
			return err
		}
		status, err := tx.rxDB.LoadStatus(aud, esub)
		if err != nil {
			return err
		}
		props := make(map[caep.EventScope]string)
		for _, es := range status.EventScopes[et] {
			css, err := tx.trans.CtxScopes(et, []caep.EventScope{es})
			if err != nil {
				return err
			}
			props[es] = c.Value(css[0])
		}
		e := &caep.Event{
			Type:     et,
			Subject:  esub,
			Property: props,
		}
		if err := tx.caep.Transmit(context, aud, e); err != nil {
			return fmt.Errorf("送信に失敗 Rx(%v) e(%v) because %v\n", aud, e, err)
		}
	}
	return nil
}

// addsubverifier は caep.verifier を満たす
type verifier struct {
	uma   *umaResSrv
	rxs   *rxDB
	trans TranslaterForCAEP
}

var _ caep.Verifier = &verifier{}

func (v *verifier) AddSub(authHeader string, req *caep.ReqAddSub) (caep.RxID, *caep.StreamStatus, error) {
	tok, err := v.uma.uma.VerifyAuthorizationHeader(authHeader)
	if err != nil {
		var ctxReq []struct {
			id     ctx.ID
			scopes []ctx.Scope
		}
		for et, r := range req.ReqEventScopes {
			id, err := v.trans.CtxID(r.EventID)
			if err != nil {
				return "", nil, err
			}
			scopes, err := v.trans.CtxScopes(et, r.Scopes)
			if err != nil {
				return "", nil, err
			}
			ctxReq = append(ctxReq, struct {
				id     ctx.ID
				scopes []ctx.Scope
			}{id, scopes})
		}
		if err := v.uma.permissionTicket(context.Background(), ctxReq); err != nil {
			return "", nil, err
		}
	}
	rxID, ok := extractRxIDFromToken(tok)
	if !ok {
		return caep.RxID(""), nil, fmt.Errorf("RxID を RPT から取得できなかった %#v", tok)
	}
	for _, r := range req.ReqEventScopes {
		ctxID, err := v.trans.CtxID(r.EventID)
		if err != nil {
			fmt.Printf("AddSub で EventID -> ctxID の変換に失敗 %v\n", err)
			return "", nil, fmt.Errorf("AddSub で EventID -> ResID の変換に失敗 %v\n", err)
		}
		if err := v.trans.BindEventSubjectToCtxID(rxID, req.Subject, ctxID); err != nil {
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
	if err := v.rxs.setExpiration(rxID, req.Subject, tok.Expiration()); err != nil {
		fmt.Printf("cannot settign expiration %v\n", err)
	}
	return rxID, status, nil
}

func (v *verifier) Stream(authHeader string) (caep.RxID, error) {
	tok, err := v.uma.uma.VerifyAuthorizationHeader(authHeader)
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
	tok, err := v.uma.uma.VerifyAuthorizationHeader(authHeader)
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

// extractRxIDFromToken は jwt.Token の azp クレームから Receiver ID を取得する。
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

// permittedEventScopesFromToken は Keycloak の RPT トークンである jwt.Token から許可されたリソースへのスコープを抽出する
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
		cName, ok := v9.(string)
		slice := strings.Split(cName, ":s:")
		ct := strings.TrimPrefix(slice[0], "c:")
		eventscopes[caep.EventType(string(ct))] = scopes
	}
	return eventscopes, nil
}

type rxDB struct {
	trans        TranslaterForCAEP
	notification func(ctx.Sub, []ctx.Type) error
	m            sync.RWMutex
	stream       map[caep.RxID]*caep.StreamConfig
	status       map[caep.RxID]map[string]struct {
		status     *caep.StreamStatus
		expiration time.Time
	}

	rxIDs map[string]map[caep.RxID]bool
}

var _ caep.StreamConfigRepo = &rxDB{}
var _ caep.SubStatusRepo = &rxDB{}

func (rxs *rxDB) auds(ct ctx.Type) map[caep.RxID]bool {
	rxs.m.RLock()
	defer rxs.m.RUnlock()
	return rxs.rxIDs[ct.String()]
}

func (rxs *rxDB) setExpiration(rxID caep.RxID, esub *caep.EventSubject, expiraiton time.Time) error {
	rxs.m.Lock()
	defer rxs.m.Unlock()
	v, ok := rxs.status[rxID]
	if !ok {
		v = make(map[string]struct {
			status     *caep.StreamStatus
			expiration time.Time
		})
	}
	s, ok := v[esub.Identifier()]
	if !ok {
		s = struct {
			status     *caep.StreamStatus
			expiration time.Time
		}{}
	}
	s.expiration = expiraiton
	v[esub.Identifier()] = s
	rxs.status[rxID] = v
	return nil
}

func (rxs *rxDB) LoadStatus(rxID caep.RxID, esub *caep.EventSubject) (*caep.StreamStatus, error) {
	rxs.m.RLock()
	defer rxs.m.RUnlock()
	v, ok := rxs.status[rxID]
	if !ok {
		return nil, fmt.Errorf("")
	}
	s, ok := v[esub.Identifier()]
	if !ok {
		return nil, fmt.Errorf("")
	}
	if !s.expiration.IsZero() {
		if time.Now().Before(s.expiration.Round(0).Add(10 * time.Second)) {
			s.status.Status = "disabled"
			return s.status, nil
		}
	}
	return s.status, nil
}

func (rxs *rxDB) SaveStatus(rxID caep.RxID, status *caep.StreamStatus) error {
	rxs.m.Lock()
	defer rxs.m.Unlock()
	v, ok := rxs.status[rxID]
	if !ok {
		v = make(map[string]struct {
			status     *caep.StreamStatus
			expiration time.Time
		})
	}
	s, ok := v[status.Subject.Identifier()]
	if !ok {
		s = struct {
			status     *caep.StreamStatus
			expiration time.Time
		}{}
	}
	s.status = status
	v[status.Subject.Identifier()] = s
	rxs.status[rxID] = v
	cs, err := rxs.trans.CtxSub(rxID, &status.Subject)
	if err != nil {
		return err
	}
	var cts []ctx.Type
	for et := range status.EventScopes {
		cts = append(cts, rxs.trans.CtxType(et))
	}
	if err := rxs.notification(cs, cts); err != nil {
		return err
	}
	return nil
}

func (rxs *rxDB) LoadStream(rxID caep.RxID) (*caep.StreamConfig, error) {
	rxs.m.RLock()
	defer rxs.m.RUnlock()
	c, ok := rxs.stream[rxID]
	if !ok {
		return nil, fmt.Errorf("cannot find stream config of Rx(%v)", rxID)
	}
	return c, nil
}

func (rxs *rxDB) SaveStream(rxID caep.RxID, stream *caep.StreamConfig) error {
	rxs.m.Lock()
	defer rxs.m.Unlock()
	rxs.stream[rxID] = stream
	for _, et := range stream.EventsDelivered {
		ct := rxs.trans.CtxType(caep.EventType(et))
		auds, ok := rxs.rxIDs[ct.String()]
		if !ok {
			auds = make(map[caep.RxID]bool)
		}
		auds[rxID] = true
		rxs.rxIDs[ct.String()] = auds
	}
	return nil
}
