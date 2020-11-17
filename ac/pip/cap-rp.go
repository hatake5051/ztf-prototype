package pip

import (
	"context"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/hatake5051/ztf-prototype/ac"
	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/uma"
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
		return nil, newE(err, CtxsNotFound)
	}
	return ctxs, nil
}

func (cm *caprp) Agent() (ac.CtxAgent, error) {
	return &ctxagent{
		cm.sm.Agent(),
		cm.recv.recv.Recv,
	}, nil
}

func (cm *caprp) setCtx(spagID string, c *caep.Context) error {
	print("caeprecv spagid:%s context:%v  ", spagID, c)
	return cm.db.Set(spagID, fromCAEPCtx(c))
}

// AuthNForCAEPRecvConf は CAEP の Receriver でサブジェクト認証を管理するための設定情報
type AuthNForCAEPRecvConf struct {
	CAPName string
	OIDCRP  *OIDCRPConf
}

func (c *AuthNForCAEPRecvConf) new(sm smForCtxManager) *authNForCAEPRecv {
	return &authNForCAEPRecv{c.CAPName, sm, c.OIDCRP}
}

// authNForCAEPRecv は 受け取りたいコンテキストのサブジェクトの認証を担う
// またセッションを管理する
type authNForCAEPRecv struct {
	capName    string
	sm         smForCtxManager
	oidcrpConf *OIDCRPConf
}

// GetSub は session に紐づくサブジェクトがいればそれを返す。
// session と紐づくサブジェクトがいなければ未認証エラーを返す
func (a *authNForCAEPRecv) GetSub(session string) (*subForCtx, error) {
	// subject for context を session から取得
	sub, err := a.sm.Load(session)
	if err != nil {
		// 認証できてないことをエラーとして表現
		return nil, newEO(err, SubjectForCtxUnAuthenticated, a.capName)
	}
	return sub, nil
}

func (a *authNForCAEPRecv) Agent() *authnagent {
	oidcrp := a.oidcrpConf.new()
	return &authnagent{
		oidcrp:     oidcrp,
		setSubject: a.setSub,
	}
}

// setSub はOIDC 認証フローで獲得できた IDToken をセッションに保存する
func (a *authNForCAEPRecv) setSub(session string, token *oidc.IDToken) error {
	sub := &subForCtx{token.Subject}
	if err := a.sm.Set(session, sub); err != nil {
		return err
	}
	return nil
}

// CAEPRecvConf は CAEP の Receiver となるための設定情報
type CAEPRecvConf struct {
	CAEPRecv *caep.RecvConf
	// Oauth2Conf は stream config/status endpoit の保護に使う
	Oauth2Conf *clientcredentials.Config
	// UMAConf は sub add endpoint の保護に使う
	UMAConf *UMAClientConf
}

func (c *CAEPRecvConf) new(db umaClientDB, setCtx caep.SetCtx) (*caeprecv, error) {
	umaCli, err := c.UMAConf.new(db)
	if err != nil {
		return nil, err
	}
	t, err := c.Oauth2Conf.Token(context.Background())
	if err != nil {
		return nil, err
	}
	caeprecv := &caeprecv{uma: umaCli}
	recv, err := c.CAEPRecv.New(t, umaCli, setCtx)
	caeprecv.recv = recv
	return caeprecv, nil
}

type caeprecv struct {
	recv caep.Recv
	uma  *umaClient
}

// stream の config が req を満たしているかチェック
// 満たしているとは req に含まれる ctx.ID が全て config.EventRequested に含まれているか
func (cm *caeprecv) SetupStream(req []reqCtx) error {
	// 最新の StreamConf を読む
	conf, err := cm.recv.ReadCtxStream()
	if err != nil {
		// err 内容が Access Token がないときは
		if err, ok := err.(caep.RecvError); ok && err.Code() == caep.NoOAuthTokenForConfigStream {
			// get AccessToken をするが、今回は client credential でやってるので init 事に持ってるはず
			return err
		}
		// conf をまだ設定していないものとする
		conf = cm.recv.DefaultCtxStreamConfig()
	}
	var reqCtxID []string
	for _, c := range req {
		reqCtxID = append(reqCtxID, c.ID)
	}
	if ismodified := conf.UpdateCtxsRequested(reqCtxID); !ismodified {
		return nil
	}
	// conf を更新する
	conf, err = cm.recv.UpdateCtxStream(conf)
	if err != nil {
		// 更新に失敗したら、終わり
		return err
	}
	return nil
}

func (cm *caeprecv) IsEnabledStatusFor(sub *subForCtx) error {
	// subject の stream での status を得る
	status, err := cm.recv.ReadCtxStreamStatus(sub.toCAEP())
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
	reqctxForCAEP := (reqCtxList(req)).castToCAEPCtxList()
	err := cm.recv.AddSubject(sub.toCAEP(), reqctxForCAEP)
	if err == nil {
		// 追加に成功
		return nil
	}
	e, ok := err.(caep.RecvError)
	if !ok {
		// ここでは、対処しないエラー
		return err
	}
	// PermissionTicket が発行されたら
	if e.Code() == caep.UMAUnAuthorizedWithPermissionTicket {
		// RPT 要求を行う
		if err := cm.uma.ReqRPT(sub); err != nil {
			return err
		}
		// RPT 要求に成功すると、もう一度 AddSubjectを行う
		return cm.recv.AddSubject(sub.SpagID, reqctxForCAEP)
	}
	return nil
}

func (sub *subForCtx) toCAEP() string {
	return sub.SpagID
}

// reqCtxList は []reqCtx を []caep.Context に変換するためのメソッドを持つ
type reqCtxList []reqCtx

func (req reqCtxList) castToCAEPCtxList() []caep.Context {
	var caepctxs []caep.Context
	for _, c := range req {
		caepctxs = append(caepctxs, caep.Context{
			ID:     c.ID,
			Scopes: c.Scopes,
		})
	}
	return caepctxs
}

// UMAClientConf は CAP で UMAClint となるための設定情報
type UMAClientConf struct {
	// 認可サーバの名前
	AuthZSrvName string
	// Requesting Party のクレデンシャル情報
	ReqPartyCredential struct {
		Name string
		Pass string
	}
	// 認可サーバアクセスのためのトークンを OAuth2.0 で
	Oauth2Conf *oauth2.Config
}

type umaClientDB interface {
	SetPermissionTicket(spagID string, ticket string) error
	LoadPermissionTicket(sub *subForCtx) (string, error)
	SetRPT(sub *subForCtx, tok *uma.RPT) error
	LoadRPT(spagID string) (*uma.RPT, error)
}

func (conf *UMAClientConf) new(db umaClientDB) (*umaClient, error) {
	rqpName := conf.ReqPartyCredential.Name
	rqpPass := conf.ReqPartyCredential.Pass
	tok, err := conf.Oauth2Conf.PasswordCredentialsToken(context.Background(), rqpName, rqpPass)
	if err != nil {
		return nil, err
	}
	authZSrv, err := uma.NewAuthZSrv(conf.AuthZSrvName)
	if err != nil {
		return nil, err
	}
	return &umaClient{tok, authZSrv, db}, nil
}

// umaClient は caep.Receiver が add subject するときの RPT を管理する
type umaClient struct {
	tok      *oauth2.Token
	authZSrv *uma.AuthZSrv
	db       umaClientDB
}

// ExtractPermissionTicket は uma Resource server からのレスポンスから PermissionTicket を抽出しサブジェクトと紐付ける
func (u *umaClient) ExtractPermissionTicket(spagID string, resp *http.Response) error {
	pt, err := uma.InitialPermissionTicket(resp)
	if err != nil {
		return err
	}
	if pt.InitialOption.AuthZSrv != u.authZSrv.Issuer {
		return fmt.Errorf("sould be equeal Metadata Issuer: %v, resp: %v", u.authZSrv.Issuer, pt.InitialOption.AuthZSrv)
	}
	return u.db.SetPermissionTicket(spagID, pt.Ticket)
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
	tok, err := uma.ReqRPT(u.authZSrv.TokenURL, ticket, func(r *http.Request) {
		u.tok.SetAuthHeader(r)
	})
	if err != nil {
		if err, ok := err.(uma.Error); ok {
			return newE(err, SubjectForCtxUnAuthorizeButReqSubmitted)
		}
		return err
	}
	return u.db.SetRPT(sub, tok)
}

// func contains(src []string, x string) bool {
// 	for _, s := range src {
// 		if s == x {
// 			return true
// 		}
// 	}
// 	return false
// }

// // forall a in x, a in src ;then true
// func isSubSlice(src []string, x []string) bool {
// 	for _, a := range x {
// 		if !contains(src, a) {
// 			return false
// 		}
// 	}
// 	return true
// }
