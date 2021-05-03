package cap

import (
	"fmt"
	"mime"
	"net/http"
	"sync"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/openid"
	"github.com/hatake5051/ztf-prototype/uma"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

// New は CAP のサーバを構築する
func (c *Conf) New() *mux.Router {
	// CAP でのセッションを管理する store を構築
	store := &sessionStoreForCAP{
		sessions.NewCookieStore([]byte("super-secret-key")),
	}

	// CAP でのコンテキストデータベースを構築
	var db CtxDB
	var ctxs []ctxType
	ctxBase := map[ctxType]ctx{}
	for ctxType, scopes := range c.CAP.Contexts {
		ctxs = append(ctxs, ctxType)
		ctxBase[ctxType] = ctx{
			Type:   ctxType,
			Scopes: scopes,
		}
	}
	db = &ctxDB{
		all:     ctxs,
		ctxBase: ctxBase,
	}

	// CAP のUMAリソースサーバ 機能を構築
	u := c.UMA.to().New(&ressrvDB{})
	us := newUMASrv(u, db, store)

	// CAEP Receiver を構築
	jwtURL := "http://idp.ztf-proto.k3.ipv6.mobi/auth/realms/context-share/protocol/openid-connect/certs"
	v := &addsubverifier{
		verifier{jwtURL},
		u,
		db,
	}
	recvRepo := &trStreamDB{db: make(map[string]caep.Receiver)}
	var eventsupported []string
	for ct := range c.CAP.Contexts {
		eventsupported = append(eventsupported, string(ct))
	}
	for recvID, v := range c.CAEP.Receivers {
		recvRepo.Save(&caep.Receiver{
			ID:   recvID,
			Host: v.Host,
			StreamConf: &caep.StreamConfig{
				Iss:             c.CAEP.Metadata.Issuer,
				Aud:             []string{v.Host},
				EventsSupported: eventsupported,
			},
		})
	}
	recvs := &recvs{
		inner: recvRepo,
		db:    make(map[string][]string),
	}
	statusRepo := &trStatusDB{db: make(map[string]map[string]caep.StreamStatus)}

	// TODO: caep を直すのは後で
	tmp := make(map[string][]string)
	for k, v := range c.CAP.Contexts {
		var vv []string
		for _, vvv := range v {
			vv = append(vv, string(vvv))
		}
		tmp[string(k)] = vv
	}
	d := &distributer{
		inner: statusRepo,
		ctxs:  tmp,
		recvs: recvs,
	}
	tr := c.CAEP.to().New(recvs, d, v)
	d.tr = tr
	cap := &cap{

		store: store,
		rp:    c.CAP.Openid.to().New(),
		db:    db,
		distr: d,
	}
	r := mux.NewRouter()
	tr.Router(r)

	r.Handle("/", cap)
	r.HandleFunc("/ctx/recv", cap.Recv)
	r.HandleFunc("/oidc/callback", cap.OIDCCallback)
	r.Use(cap.OIDCMW)
	r.HandleFunc("/list", cap.CtxList)
	suma := r.PathPrefix("/uma").Subrouter()
	suma.HandleFunc("/list", us.List)
	suma.HandleFunc("/ctx", us.CRUD)
	suma.HandleFunc("/pat/callback", us.CallBack)
	return r
}

// SubAtCAP は CAP でのサブジェクト識別子
// CAP が理解できる
type SubAtCAP string

// SessionStore は CAP のセッションを管理する
type SessionStore interface {
	SessionStoreForUMAResSrv
	PreferredName(r *http.Request) (string, error)
	SetIdentity(r *http.Request, w http.ResponseWriter, sub SubAtCAP, preferredName string) error
}

// CtxDB は CAP のコンテキストデータベースとして機能する
type CtxDB interface {
	CtxDBForUMAResSrv
	// All は管理対象のコンテキスト一覧を返す
	All() []ctxType
}

type cap struct {
	rp    openid.RP
	store SessionStore
	db    CtxDB
	distr *distributer
}

func (c *cap) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, err := c.store.PreferredName(r)
	if err != nil {
		http.Error(w, "ユーザを識別できません", http.StatusUnauthorized)
		return
	}
	s := fmt.Sprintf("<html><head/><body><h1>%sさん、こんにちは</h1>", name)
	s += `<a href="/list">コンテキストを管理する</a><br/>`
	s += `<a href="/uma/list>認可サーバへ登録済みコンテキスト一覧</a>`
	s += "</body></html>"
	w.Write([]byte(s))

}

func (c *cap) OIDCMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/callback" || r.URL.Path == "/ctx/recv" {
			next.ServeHTTP(w, r)
			return
		}
		if _, err := c.store.IdentifySubject(r); err != nil {
			c.store.SetRedirectBack(r, w, r.URL.String())
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
	err = c.store.SetIdentity(r, w, SubAtCAP(idToken.Subject()), idToken.PreferredUsername())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, c.store.LoadRedirectBack(r), http.StatusFound)
}

func (c *cap) Recv(w http.ResponseWriter, r *http.Request) {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if contentType != "application/secevent+jwt" {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tok, err := jwt.Parse(r.Body, jwt.WithVerify(jwa.HS256, []byte("for-agent-sending")))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	v, ok := tok.Get("events")
	if !ok {
		http.Error(w, "送られてきたSETに events property がない", http.StatusInternalServerError)
		return
	}
	e, ok := caep.NewSETEventsClaimFromJson(v)
	if !ok {
		http.Error(w, "送られてきたSET events property のパースに失敗", http.StatusInternalServerError)
		return
	}
	c.distr.RecvAndDistribute(e)
}

func (c *cap) CtxList(w http.ResponseWriter, r *http.Request) {
	name, _ := c.store.PreferredName(r)
	sub, err := c.store.IdentifySubject(r)
	if err != nil {
		http.Error(w, "ユーザを識別できない", http.StatusInternalServerError)
		return
	}

	s := fmt.Sprintf("<html><head/><body><h1>%sさん、こんにちは</h1>", name)
	s += "<h1>コンテキスト一覧</h1>"
	s += "<ul>"
	for _, ctxType := range c.db.All() {
		s += fmt.Sprintf("<li>ctx(%s)は認可サーバで保護", ctxType)
		c, err := c.db.Load(sub, ctxType)
		if err != nil {
			s += fmt.Sprintf("[何らかのエラーが発生] %#v", err)
		}
		if c.IDAtAuthZSrv != "" {
			s += fmt.Sprintf(`されています。 => <a href="/uma/ctx?t=%s">詳細を見る</a>`, ctxType)
		} else {
			s += `されていません。=> <form action="/uma/ctx" method="POST">`
			s += fmt.Sprintf(`<input type="hidden" name="t" value="%s"> `, ctxType)
			s += `<button type="submit">保護する</button></form>`
		}
		s += "</li>"
	}
	s += "</ul></body></html>"
	// んー、<> をエスケープしない
	w.Write([]byte(s))
}

// SessionStore の実装
type sessionStoreForCAP struct {
	store sessions.Store
}

func (s *sessionStoreForCAP) IdentifySubject(r *http.Request) (SubAtCAP, error) {
	session, err := s.store.Get(r, "CAP_AUTHN")
	if err != nil {
		return "", err
	}
	sub, ok := session.Values["subject"].(string)
	if !ok {
		return "", fmt.Errorf("ユーザを識別できない")
	}
	return SubAtCAP(sub), nil
}

func (s *sessionStoreForCAP) PreferredName(r *http.Request) (string, error) {
	session, err := s.store.Get(r, "CAP_AUTHN")
	if err != nil {
		return "", err
	}

	name, ok := session.Values["preferredName"].(string)
	if !ok {
		return "", fmt.Errorf("ユーザを識別できない")
	}
	return name, nil
}
func (s *sessionStoreForCAP) SetIdentity(r *http.Request, w http.ResponseWriter, sub SubAtCAP, preferredName string) error {
	session, err := s.store.Get(r, "CAP_AUTHN")
	if err != nil {
		return err
	}
	session.Values["preferredName"] = preferredName
	session.Values["subject"] = string(sub)
	if err := session.Save(r, w); err != nil {

		return err
	}
	return nil
}

func (s *sessionStoreForCAP) LoadRedirectBack(r *http.Request) (redirectURL string) {
	session, err := s.store.Get(r, "CAP_AUTHN")
	if err != nil {
		return ""
	}
	fmt.Printf("Load Session %#v\n", session.Values)
	red, ok := session.Values["return-address"].(string)
	if !ok {
		return ""
	}
	return red
}

func (s *sessionStoreForCAP) SetRedirectBack(r *http.Request, w http.ResponseWriter, redirectURL string) error {
	session, err := s.store.Get(r, "CAP_AUTHN")
	if err != nil {
		return err
	}
	session.Values["return-address"] = redirectURL
	fmt.Printf("Set Session %#v\n", session.Values)
	if err := session.Save(r, w); err != nil {
		return err
	}
	return nil
}

type ctxDB struct {
	all     []ctxType       // all ctxTypes
	ctxBase map[ctxType]ctx // ctxType -> ctx のベース
	db      sync.Map        // ctxType + sub -> ctx
}

func (db *ctxDB) Load(sub SubAtCAP, ct ctxType) (*ctx, error) {
	key := string(ct) + ":" + string(sub)
	v, ok := db.db.Load(key)
	fmt.Printf("Loaded %#v\n", v)
	if !ok {
		ctx := db.ctxBase[ct]
		ctx.Name = key
		fmt.Printf("Aaaa %#v\n", ctx)
		db.db.Store(key, ctx)
		return &ctx, nil
	}
	c, ok := v.(ctx)
	if !ok {
		return nil, fmt.Errorf("invalid")
	}
	return &c, nil
}

func (db *ctxDB) SaveIDAtAuthZSrv(sub SubAtCAP, ct ctxType, idAtAuthZSrv uma.ResID) error {
	key := string(ct) + ":" + string(sub)
	v, ok := db.db.Load(key)
	if !ok {
		return fmt.Errorf("not found")
	}
	c, ok := v.(ctx)
	if !ok {
		return fmt.Errorf("not found")
	}
	c.IDAtAuthZSrv = idAtAuthZSrv
	fmt.Printf("aaa %#v\n", c)
	db.db.Store(key, c)
	return nil
}

func (db *ctxDB) All() []ctxType {
	return db.all
}

// ressrvDB は UMAリソースサーバ として機能する際の uma.ResSrvDB を実装する
type ressrvDB struct {
	// // patdb は SubAtResSrv をキーとして PAT を保存する
	patdb sync.Map
	// // statedb は OAuth2.0 state をキーとして SubAtResSrv を保存数r
	statedb sync.Map
}

func (db *ressrvDB) LoadPAT(sub uma.SubAtResSrv) (*uma.PAT, error) {
	v, ok := db.patdb.Load(string(sub))
	if !ok {
		return nil, fmt.Errorf("never stored")
	}
	t, ok := v.(*uma.PAT)
	if !ok {
		return nil, fmt.Errorf("invalid type pat stored %s", sub)
	}
	return t, nil
}

func (db *ressrvDB) SavePAT(sub uma.SubAtResSrv, pat *uma.PAT) error {
	db.patdb.Store(string(sub), pat)
	return nil
}

func (db *ressrvDB) LoadPATOfResSrv() (*uma.PAT, error) {
	v, ok := db.patdb.Load("")
	if !ok {
		return nil, fmt.Errorf("never stored")
	}
	t, ok := v.(*uma.PAT)
	if !ok {
		return nil, fmt.Errorf("invalid type pat of res srv stored")
	}
	return t, nil
}

func (db *ressrvDB) SavePATOfResSrv(pat *uma.PAT) error {
	db.patdb.Store("", pat)
	return nil
}

func (db *ressrvDB) SaveOAuthState(state string, sub uma.SubAtResSrv) error {
	db.statedb.Store(state, sub)
	return nil
}

func (db *ressrvDB) LoadAndDeleteOAuthState(state string) (uma.SubAtResSrv, error) {
	v, ok := db.statedb.LoadAndDelete(state)
	if !ok {
		return uma.SubAtResSrv(""), fmt.Errorf("invalid state = %s", state)
	}
	id, ok := v.(uma.SubAtResSrv)
	if !ok {
		return uma.SubAtResSrv(""), fmt.Errorf("invalid state = %s", state)
	}
	return id, nil
}
