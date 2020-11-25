package pip

import (
	"context"
	"fmt"
	"net/http"

	acpip "github.com/hatake5051/ztf-prototype/ac/pip"
	"github.com/hatake5051/ztf-prototype/caep"
	ztfopenid "github.com/hatake5051/ztf-prototype/openid"
	"github.com/hatake5051/ztf-prototype/uma"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/lestrrat-go/jwx/jwt/openid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// CAPRPConf は CAP の RP となるための設定情報
// CAP に subject を登録するために subject 認証を行う
// CAP に stream を設定するために OAuth 認可を行う
// CAP に subject を登録するために UMA 認可を行う
type CAPRPConf struct {
	AuthN *AuthNForCAEPRecvConf
	Recv  *CAEPRecvConf
}

// new は CAPRP を ctxManager implements する
func (conf *CAPRPConf) new(sm smForCtxManager, db ctxDB, umaClientDB umaClientDB) (ctxManager, error) {
	sm1 := conf.AuthN.new(sm)
	crp := &caprp{
		sm: sm1,
		db: db,
	}
	recv1, err := conf.Recv.new(umaClientDB, crp.setCtx)
	if err != nil {
		return nil, err
	}
	crp.recv = recv1
	return crp, nil
}

// caprp は ctxManager implemantation
// cap から ctx を収集する
// TODO さらに own domain で収集した ctx を cap へ提供する
type caprp struct {
	sm   *authNForCAEPRecv
	recv *caeprecv
	db   ctxDB
}

func (cm *caprp) Get(session string, req []reqCtx) ([]ctx, error) {
	// caep.EventStream を設定しておく
	if err := cm.recv.SetupStream(req); err != nil {
		return nil, err
	}
	// subject for context を session から取得
	sub, err := cm.sm.GetSub(session)
	if err != nil {
		// err は pip.Error(未認証) を満たす場合あり
		return nil, err
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

func (cm *caprp) Agent() (acpip.CtxAgent, error) {
	return &ctxagent{
		cm.sm.Agent(),
		cm.recv.Recv,
	}, nil
}

func (cm *caprp) setCtx(spagID string, c *ctx) error {
	fmt.Printf("caeprecv spagid:%s context:%v  \n", spagID, c)
	return cm.db.Set(spagID, c)
}

// AuthNForCAEPRecvConf は CAEP の Receriver でサブジェクト認証を管理するための設定情報
type AuthNForCAEPRecvConf struct {
	CAPName string
	OIDCRP  *ztfopenid.Conf
}

func (c *AuthNForCAEPRecvConf) new(sm smForCtxManager) *authNForCAEPRecv {
	return &authNForCAEPRecv{c.CAPName, sm, c.OIDCRP}
}

// authNForCAEPRecv は 受け取りたいコンテキストのサブジェクトの認証を担う
// またセッションを管理する
type authNForCAEPRecv struct {
	capName    string
	sm         smForCtxManager
	oidcrpConf *ztfopenid.Conf
}

// GetSub は session に紐づくサブジェクトがいればそれを返す。
// session と紐づくサブジェクトがいなければ未認証エラーを返す
func (a *authNForCAEPRecv) GetSub(session string) (*subForCtx, error) {
	// subject for context を session から取得
	sub, err := a.sm.Load(session)
	if err != nil {
		// 認証できてないことをエラーとして表現
		return nil, newEO(err, acpip.SubjectForCtxUnAuthenticated, a.capName)
	}
	return sub, nil
}

func (a *authNForCAEPRecv) Agent() *authnagent {
	oidcrp := a.oidcrpConf.New()
	return &authnagent{
		oidcrp,
		a.setSub,
	}
}

// setSub はOIDC 認証フローで獲得できた IDToken をセッションに保存する
func (a *authNForCAEPRecv) setSub(session string, token openid.Token) error {
	sub := &subForCtx{token.Subject()}
	if err := a.sm.Set(session, sub); err != nil {
		return err
	}
	return nil
}

func (sub *subForCtx) toCAEP() string {
	return sub.SpagID
}

// CAEPRecvConf は CAEP の Receiver となるための設定情報
type CAEPRecvConf struct {
	CAEPRecv *caep.RecvConf
	// Oauth2Conf は stream config/status endpoit の保護に使う
	Oauth2Conf *clientcredentials.Config
	// UMAConf は sub add endpoint の保護に使う
	UMAConf *UMAClientConf
}

func (c *CAEPRecvConf) new(db umaClientDB, setCtx func(spagID string, c *ctx) error) (*caeprecv, error) {
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
	return &caeprecv{recv, setCtx, umaCli}, nil
}

type setAuthHeaders struct {
	uma *umaClient
	t   *oauth2.Token
}

func (s *setAuthHeaders) ForConfig(r *http.Request) {
	s.t.SetAuthHeader(r)
}

func (s *setAuthHeaders) ForSubAdd(spagID string, r *http.Request) {
	rpt, err := s.uma.RPT(spagID)
	if err != nil {
		return
	}
	rpt.SetAuthHeader(r)
}

type caeprecv struct {
	recv   caep.Recv
	setCtx func(spagID string, c *ctx) error
	uma    *umaClient
}

// stream の config が req を満たしているかチェック
// 満たしているとは req に含まれる ctx.ID が全て config.EventRequested に含まれているか
func (cm *caeprecv) SetupStream(req []reqCtx) error {
	var reqCtxID []string
	for _, c := range req {
		reqCtxID = append(reqCtxID, c.ID)
	}
	newConf := &caep.StreamConfig{
		EventsRequested: reqCtxID,
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
	reqscopes := make(map[string][]string)
	for _, r := range req {
		reqscopes[r.ID] = r.Scopes
	}
	reqadd := &caep.ReqAddSub{
		Sub: struct {
			SubType string "json:\"subject_type\""
			SpagID  string "json:\"spag_id\""
		}{"spag", sub.toCAEP()},
		ReqEventScopes: reqscopes,
	}
	err := cm.recv.AddSubject(reqadd)
	if err == nil {
		return nil
	}
	e, ok := err.(caep.RecvError)
	if !ok {
		return err
	}
	if e.Code() == caep.RecvErrorCodeUnAuthorized {
		resp := e.Option().(*http.Response)
		if err := cm.uma.ExtractPermissionTicket(sub.toCAEP(), resp); err != nil {
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

func (cm *caeprecv) Recv(r *http.Request) error {
	event, err := cm.recv.Recv(r)
	if err != nil {
		return err
	}
	spagID := event.Subject.SpagID
	c := &ctx{
		ID:          event.ID,
		ScopeValues: event.Property,
	}
	return cm.setCtx(spagID, c)
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
	umaconf := uma.Conf{
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
	SetPermissionTicket(spagID string, ticket *uma.PermissionTicket) error
	LoadPermissionTicket(sub *subForCtx) (*uma.PermissionTicket, error)
	SetRPT(sub *subForCtx, tok *uma.RPT) error
	LoadRPT(spagID string) (*uma.RPT, error)
}

// umaClient は caep.Receiver が add subject するときの RPT を管理する
type umaClient struct {
	rawidt string
	cli    uma.Client
	db     umaClientDB
}

// ExtractPermissionTicket は uma Resource server からのレスポンスから PermissionTicket を抽出しサブジェクトと紐付ける
func (u *umaClient) ExtractPermissionTicket(spagID string, resp *http.Response) error {
	pt, err := u.cli.ExtractPermissionTicket(resp)
	if err != nil {
		return err
	}
	return u.db.SetPermissionTicket(spagID, pt)
}

// RPT はサブジェクトと紐づいた Requesting Party Token を取得する
func (u *umaClient) RPT(spagID string) (*uma.RPT, error) {
	return u.db.LoadRPT(spagID)
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
