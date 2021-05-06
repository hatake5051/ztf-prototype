package pip

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"

	acpip "github.com/hatake5051/ztf-prototype/ac/pip"
	"github.com/hatake5051/ztf-prototype/caep"
	ztfopenid "github.com/hatake5051/ztf-prototype/openid"
	"github.com/hatake5051/ztf-prototype/uma"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// CAPRPConf は CAP の RP となるための設定情報
// CAP に subject を登録するために subject 認証を行う
// CAP に stream を設定するために OAuth 認可を行う
// CAP に subject を登録するために UMA 認可を行う
type CAPRPConf struct {
	Recv *CAEPRecvConf
}

// new は CAPRP を ctxManager implements する
func (conf *CAPRPConf) new(sm smForCtxManager, db ctxDB, umaClientDB umaClientDB) (ctxManager, error) {
	recv, err := conf.Recv.new(umaClientDB, db)
	if err != nil {
		return nil, err
	}
	crp := &caprp{
		sm:   sm,
		db:   db,
		recv: recv,
	}

	return crp, nil
}

// caprp は ctxManager implemantation
// cap から ctx を収集する
// TODO さらに own domain で収集した ctx を cap へ提供する
type caprp struct {
	sm   smForCtxManager
	recv *caeprecv
	db   ctxDB
}

var _ ctxManager = &caprp{}

func (cm *caprp) SetUMAResID(session string, mapper map[ctxType]uma.ResID) error {
	sub, err := cm.sm.Load(session)
	if err != nil {
		// // subForCtx をランダムに生成して保存
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		pid := base64.URLEncoding.EncodeToString(b)
		sub = &subForCtx{pid, ""}
		if err := cm.sm.Set(session, sub); err != nil {
			return err
		}
	}
	var req []reqCtx
	for ct, _ := range mapper {
		req = append(req, reqCtx{Type: ct})
	}
	ctxs, _ := cm.db.Load(sub, req)
	for ct, resID := range mapper {
		c := &ctx{Sub: sub, Type: ct, ResID: resID}
		for _, c2 := range ctxs {
			if c2.Type == ct {
				c.ScopeValues = c2.ScopeValues
				break
			}
		}
		if err := cm.db.Set(c); err != nil {
			return err
		}
	}
	return nil
}

func (cm *caprp) Get(session string, req []reqCtx) ([]ctx, error) {
	// caep.EventStream を設定しておく
	if err := cm.recv.SetupStream(req); err != nil {
		return nil, err
	}
	// subject for context を session から取得
	var sub *subForCtx
	var err error
	sub, err = cm.sm.Load(session)
	if err != nil {
		// // subForCtx をランダムに生成して保存
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		pid := base64.URLEncoding.EncodeToString(b)
		sub = &subForCtx{pid, ""}
		if err := cm.sm.Set(session, sub); err != nil {
			return nil, err
		}
	}
	// subject の stream での status を得る
	if err := cm.recv.IsEnabledStatusFor(sub); err != nil {
		// sub が stream で enable でない、 addsub を行う
		if err := cm.recv.AddSub(sub, req); err != nil {
			// err は pip.Error(ReqSubmitted) を満たす場合あり
			return nil, err
		}
		// サブジェクトの追加に成功したら次のステップへ
	}
	// sub が stream に追加されていれば ctxs が取り出せる
	ctxs, err := cm.db.Load(sub, req)
	if err != nil {
		// まだctx が届いてないかもしれない
		return nil, newE(err, acpip.CtxsNotFound)
	}
	return ctxs, nil
}

func (cm *caprp) Agent() (acpip.RxCtxAgent, error) {
	return cm.recv, nil
}

// CAEPRecvConf は CAEP の Receiver となるための設定情報
type CAEPRecvConf struct {
	CAEPRecv *caep.RecvConf
	// Oauth2Conf は stream config/status endpoit の保護に使う
	Oauth2Conf *clientcredentials.Config
	// UMAConf は sub add endpoint の保護に使う
	UMAConf *UMAClientConf
}

func (c *CAEPRecvConf) new(db umaClientDB, ctxs ctxDB) (*caeprecv, error) {
	umaCli, err := c.UMAConf.new(db)
	if err != nil {
		return nil, err
	}
	t, err := c.Oauth2Conf.Token(context.Background())
	if err != nil {
		return nil, err
	}
	a := &setAuthHeaders{umaCli, t}
	recv := c.CAEPRecv.New(a)
	return &caeprecv{recv, ctxs, umaCli}, nil
}

type setAuthHeaders struct {
	uma *umaClient
	t   *oauth2.Token
}

func (s *setAuthHeaders) ForConfig(r *http.Request) {
	s.t.SetAuthHeader(r)
}

func (s *setAuthHeaders) ForSubAdd(sub *caep.EventSubject, r *http.Request) {
	rpt, err := s.uma.RPT(NewSubForCtxFromCAEPSub(sub))
	if err != nil {
		return
	}
	rpt.SetAuthHeader(r)
}

type caeprecv struct {
	recv caep.Rx
	ctxs ctxDB
	uma  *umaClient
}

// stream の config が req を満たしているかチェック
// 満たしているとは req に含まれる ctx.ID が全て config.EventRequested に含まれているか
func (cm *caeprecv) SetupStream(req []reqCtx) error {
	var reqCtxType []string
	for _, c := range req {
		reqCtxType = append(reqCtxType, string(c.Type))
	}
	newConf := &caep.StreamConfig{
		EventsRequested: reqCtxType,
	}
	if err := cm.recv.SetUpStream(newConf); err != nil {
		// 更新に失敗したら、終わり
		return err
	}
	return nil
}

func (cm *caeprecv) IsEnabledStatusFor(sub *subForCtx) error {
	// subject の stream での status を得る
	status, err := cm.recv.ReadStreamStatus(sub.toCAEP())
	// status が得られなかった、もしくは status.Status が有効でないとき
	if err != nil {
		return err
	}
	if status.Status != "enabled" {
		return fmt.Errorf("status for sub(%v) is not enabled but %v", sub, status)
	}
	return nil
}

func (cm *caeprecv) AddSub(sub *subForCtx, req []reqCtx) error {
	reqscopes := make(map[caep.EventType]struct {
		EventID string            `json:"event_id"`
		Scopes  []caep.EventScope `json:"scopes"`
	})
	for _, r := range req {
		et := caep.EventType(r.Type)

		resID, err := cm.ctxs.UMAResID(sub, r.Type)
		if err != nil {
			return err
		}

		var escopes []caep.EventScope
		for _, s := range r.Scopes {
			escopes = append(escopes, caep.EventScope(s))
		}

		reqscopes[et] = struct {
			EventID string            `json:"event_id"`
			Scopes  []caep.EventScope `json:"scopes"`
		}{string(resID), escopes}
	}
	reqadd := &caep.ReqAddSub{
		Subject:        sub.toCAEP(),
		ReqEventScopes: reqscopes,
	}
	err := cm.recv.AddSubject(reqadd)
	if err == nil {
		return nil
	}
	fmt.Printf("caeprecv.AddSub failed %#v\n", err)
	e, ok := err.(caep.RecvError)
	if !ok {
		return err
	}
	if e.Code() == caep.RecvErrorCodeUnAuthorized {
		resp := e.Option().(*http.Response)
		if err := cm.uma.ExtractPermissionTicket(sub, resp); err != nil {
			return err
		}
		if err := cm.uma.ReqRPT(sub); err != nil {
			return err
		}
		return cm.recv.AddSubject(reqadd)
	}
	if e.Code() == caep.RecvErrorCodeNotFound {
		// todo どうしようもないえらー
		return e
	}
	return e
}

func (cm *caeprecv) RecvCtx(r *http.Request) error {
	event, err := cm.recv.Recv(r)
	if err != nil {
		return err
	}
	sub := NewSubForCtxFromCAEPSub(event.Subject)
	props := make(map[ctxScope]string)
	for es, v := range event.Property {
		props[ctxScope(es)] = v
	}
	c := &ctx{
		Type:        ctxType(event.Type),
		ScopeValues: props,
		Sub:         sub,
	}
	return cm.ctxs.Set(c)
}

// UMAClientConf は CAP で UMAClint となるための設定情報
type UMAClientConf struct {
	// Requesting Party のクレデンシャル情報
	ReqPartyCredential struct {
		Issuer string
		Name   string
		Pass   string
	}
	// 認可サーバに対するクライアントクレデンシャル情報
	ClientCredential struct {
		AuthzSrv string
		ID       string
		Secret   string
	}
}

func (conf *UMAClientConf) new(db umaClientDB) (*umaClient, error) {
	umaconf := uma.ClientConf{
		AuthZSrv: conf.ClientCredential.AuthzSrv,
		ClientCred: struct {
			ID     string
			Secret string
		}{conf.ClientCredential.ID, conf.ClientCredential.Secret},
	}
	cli := umaconf.New()

	op, err := ztfopenid.NewOPFetched(conf.ReqPartyCredential.Issuer)
	if err != nil {
		return nil, err
	}
	rpConf := oauth2.Config{
		ClientID:     conf.ClientCredential.ID,
		ClientSecret: conf.ClientCredential.Secret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  op.AuthorizationEndpoint,
			TokenURL: op.TokenEndpoint,
		},
		Scopes: []string{"openid"},
	}
	rqpName := conf.ReqPartyCredential.Name
	rqpPass := conf.ReqPartyCredential.Pass
	tok, err := rpConf.PasswordCredentialsToken(context.Background(), rqpName, rqpPass)
	if err != nil {
		return nil, err
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("Requesting Party のIDTokenの抽出に失敗 アクセストークン: %v", tok)
	}
	jwkset, err := jwk.FetchHTTP(op.JwksURI)
	if err != nil {
		return nil, err
	}
	if _, err = jwt.ParseString(rawIDToken, jwt.WithKeySet(jwkset), jwt.WithOpenIDClaims()); err != nil {
		return nil, err
	}
	return &umaClient{rawIDToken, cli, db}, nil
}

type umaClientDB interface {
	SetPermissionTicket(*subForCtx, *uma.PermissionTicket) error
	LoadPermissionTicket(*subForCtx) (*uma.PermissionTicket, error)
	SetRPT(*subForCtx, *uma.RPT) error
	LoadRPT(*subForCtx) (*uma.RPT, error)
}

// umaClient は caep.Receiver が add subject するときの RPT を管理する
type umaClient struct {
	rawidt string
	cli    uma.Client
	db     umaClientDB
}

// ExtractPermissionTicket は uma Resource server からのレスポンスから PermissionTicket を抽出しサブジェクトと紐付ける
func (u *umaClient) ExtractPermissionTicket(sub *subForCtx, resp *http.Response) error {
	pt, err := u.cli.ExtractPermissionTicket(resp)
	if err != nil {
		return err
	}
	return u.db.SetPermissionTicket(sub, pt)
}

// RPT はサブジェクトと紐づいた Requesting Party Token を取得する
func (u *umaClient) RPT(sub *subForCtx) (*uma.RPT, error) {
	return u.db.LoadRPT(sub)
}

// ReqRPT はサブジェクトと紐づいた PermissionTicket を使って UMA 認可プロセスを開始する
func (u *umaClient) ReqRPT(sub *subForCtx) error {
	ticket, err := u.db.LoadPermissionTicket(sub)
	if err != nil {
		return err
	}
	tok, err := u.cli.ReqRPT(ticket, u.rawidt)
	if err != nil {
		if err, ok := err.(*uma.ReqRPTError); ok {
			return newE(err, acpip.SubjectForCtxUnAuthorizeButReqSubmitted)
		}
		return err
	}
	return u.db.SetRPT(sub, tok)
}
