package pip

import (
	"fmt"
	"sync"

	"github.com/hatake5051/ztf-prototype/ac"
	acpip "github.com/hatake5051/ztf-prototype/ac/pip"
	ztfopenid "github.com/hatake5051/ztf-prototype/openid"
	"github.com/lestrrat-go/jwx/jwt/openid"
)

// subject は ac.Subject の実体
type subject struct {
	ID *subIdentifier
}

func (sub *subject) ToACSub() ac.Subject {
	return &wrapS{sub}
}

// subIdentifier は subject の識別子
type subIdentifier struct {
	Iss string
	Sub string
}

// newSubID は oidc.IDToken を subIdnetifier に変換する
func newSubID(idt openid.Token) *subIdentifier {
	return &subIdentifier{idt.Issuer(), idt.Subject()}
}

// SubPIPConf は subPIP の設定情報
type SubPIPConf struct {
	// IssuerList は認証サーバとして利用可能な OP のリスト
	IssuerList []string `json:"iss_list"`
	// RPConfMap は Issuer ごとの RP 設定情報
	RPConf map[string]*ztfopenid.Conf `json:"rp_config"`
}

func (conf *SubPIPConf) new(sm smForSubPIP, db subDB) *subPIP {
	pip := &subPIP{sm: sm, db: db}
	for issuer, rpconf := range conf.RPConf {
		rp := rpconf.New()
		pip.rps.Store(issuer, &authnagent{rp, pip.set})
	}

	return pip
}

// subPIP は PIP のなかで subject を管理する
type subPIP struct {
	sm  smForSubPIP
	db  subDB
	rps sync.Map
}

// smForSubPIP は session と subIdentifier の紐付けを管理する
type smForSubPIP interface {
	Load(session string) (*subIdentifier, error)
	Set(session string, subID *subIdentifier) error
}

// subDB は 異なる OIDCRP 情報を保存し、 subject を保存する
type subDB interface {
	Load(key *subIdentifier) (*subject, error)
	Set(openid.Token) error
}

// get は PIP から subject を取得する
func (pip *subPIP) Get(session string) (*subject, error) {
	// session に対応する Subject.identifier があるか確認
	subID, err := pip.sm.Load(session)
	if err != nil {
		// なければ subject が誰か識別できておらず、セッションをはれていない
		return nil, newE(err, acpip.SubjectUnAuthenticated)
	}
	// subject.identifier をもとに subject の値をDBから取得
	sub, err := pip.db.Load(subID)
	if err != nil {
		// 見つからなければ、認証からやり直す
		return nil, newE(err, acpip.SubjectUnAuthenticated)
	}
	return sub, nil
}

// agent は OIDC フローを front で行うエージェントを生成する
func (pip *subPIP) Agent(issuer string) (ac.AuthNAgent, error) {
	v, ok := pip.rps.Load(issuer)
	if !ok {
		return nil, fmt.Errorf("このOP(%v)の設定情報がないらしい", issuer)
	}
	return v.(*authnagent), nil
}

// set は AuthNAgent が取得した oidc.IDToken を PIP に保存する
func (pip *subPIP) set(session string, sub openid.Token) error {
	subID := newSubID(sub)
	if err := pip.sm.Set(session, subID); err != nil {
		return err
	}
	if err := pip.db.Set(sub); err != nil {
		return err
	}
	return nil
}

// wrapS は subject を ac.Subject impl させるためのラッパー
type wrapS struct {
	s *subject
}

func (w *wrapS) ID() string {
	return w.s.ID.Sub
}
