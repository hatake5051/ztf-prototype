package rp

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"sync"

	"github.com/hatake5051/ztf-prototype/ac"
	"github.com/hatake5051/ztf-prototype/ac/pip"
	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/ctx"
	"github.com/hatake5051/ztf-prototype/ctx/rx"
	"github.com/hatake5051/ztf-prototype/uma"
	"github.com/lestrrat-go/jwx/jwt/openid"
)

// Repository はいろんなものを保存する場所
type Repository interface {
	KeyPrefix() string
	Save(key string, b []byte) error
	Load(key string) (b []byte, err error)
}

func NewRepo() Repository {
	return &repo{r: make(map[string][]byte)}
}

type repo struct {
	m sync.RWMutex
	r map[string][]byte
}

func (r *repo) KeyPrefix() string {
	return "repo"
}

func (r *repo) Save(key string, b []byte) error {
	r.m.Lock()
	defer r.m.Unlock()
	r.r[key] = b
	return nil
}

func (r *repo) Load(key string) (b []byte, err error) {
	r.m.RLock()
	defer r.m.RUnlock()
	b, ok := r.r[key]
	if !ok {
		return nil, fmt.Errorf("key(%s) にはまだ保存されていない", key)
	}
	return b, nil
}

type iSessionStoreForSPIP struct {
	r           Repository
	keyModifier string
}

var _ pip.SessionStoreForSPIP = &iSessionStoreForSPIP{}

func (sm *iSessionStoreForSPIP) key(session string) string {
	return sm.r.KeyPrefix() + ":" + sm.keyModifier + ":" + session
}

func (sm *iSessionStoreForSPIP) Identify(session string) (ac.Subject, error) {
	var sub s
	b, err := sm.r.Load(sm.key(session))
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(b)
	if err := gob.NewDecoder(buf).Decode(&sub); err != nil {
		return nil, err
	}
	return &sub, nil
}

func (sm *iSessionStoreForSPIP) SetIDToken(session string, idt openid.Token) error {
	sub := &s{idt.PreferredUsername()}
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(sub); err != nil {
		return nil
	}
	return sm.r.Save(sm.key(session), buf.Bytes())
}

type iSessionStoreForCPIP struct {
	r           Repository
	keyModifier string
}

var _ pip.SessionStoreForCPIP = &iSessionStoreForCPIP{}

func (sm *iSessionStoreForCPIP) key(session, cap string) string {
	return sm.r.KeyPrefix() + ":" + sm.keyModifier + ":" + cap + ":" + session
}

func (sm *iSessionStoreForCPIP) Identify(session string, cap string) ctx.Sub {
	var sub cs
	b, err := sm.r.Load(sm.key(session, cap))
	if err != nil {
		return &cs{
			sub: cap + ":" + session,
		}
	}
	buf := bytes.NewBuffer(b)
	if err := gob.NewDecoder(buf).Decode(&sub); err != nil {
		return &cs{
			sub: cap + ":" + session,
		}
	}
	return &sub
}

type iCtxDB struct {
	r           Repository // ctx.Sub + ctx.Type -> ctx.Ctx
	capBase     sync.Map   // cap -> []map[ctxtype][]ctxScope
	ctxBase     sync.Map   // ctxType -> []ctxScope
	keyModifier string
}

func (db *iCtxDB) Init(capURL string, contexts map[string][]string) {
	db.capBase.Store(capURL, contexts)
	for ct, css := range contexts {
		db.ctxBase.Store(ct, css)
	}
}

var _ pip.CtxDB = &iCtxDB{}

func (db *iCtxDB) key(sub ctx.Sub, ct ctx.Type) string {
	return db.r.KeyPrefix() + ":" + db.keyModifier + ":sub:" + sub.String() + ":ct:" + ct.String()
}

func (db *iCtxDB) Load(sub ctx.Sub, cts []ctx.Type) ([]ctx.Ctx, error) {
	var ret []ctx.Ctx
	for _, ct := range cts {
		c := c{}
		b, err := db.r.Load(db.key(sub, ct))
		if err != nil {
			continue
		}
		buf := bytes.NewBuffer(b)
		if err := gob.NewDecoder(buf).Decode(&c); err != nil {
			continue
		}
		ret = append(ret, &c)
	}
	if len(ret) == 0 {
		return nil, fmt.Errorf("sub(%v) の cts(%v) は一つもない", sub, cts)
	}
	return ret, nil
}

func (db *iCtxDB) LoadAllFromCAP(capURL string) []ctx.Ctx {
	var ctxs []ctx.Ctx
	v, ok := db.ctxBase.Load(capURL)
	if ok {
		return nil
	}
	for ct, css := range v.(map[string][]string) {
		ctxs = append(ctxs, &c{
			typ:    ct,
			scopes: css,
		})
	}
	return ctxs
}

func (db *iCtxDB) SaveCtxFrom(e *caep.Event) error {
	sub := NewCtxSubFromEventSubject(e.Subject)
	ct := ctx.NewCtxType(string(e.Type))
	v, ok := db.ctxBase.Load(ct.String())
	if !ok {
		return fmt.Errorf("event(%v) の type が対応していないため保存できない")
	}
	scopes := v.([]string)

	var prevCtx c
	// 以前に登録したものがあるか
	if b, err := db.r.Load(db.key(sub, ct)); err == nil {
		buf := bytes.NewBuffer(b)
		if err := gob.NewDecoder(buf).Decode(&prevCtx); err != nil {
			return fmt.Errorf("db.r.Load in SaveCtxFrom(%v) で失敗 %v", e, err)
		}
	} else {
		prevCtx = c{
			scopes: scopes,
		}
	}

	c := newCtxFromEvent(e, &prevCtx)
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(c); err != nil {
		return err
	}
	return db.r.Save(db.key(sub, ct), buf.Bytes())
}

var _ rx.Translater = &iCtxDB{}

func (tr *iCtxDB) CtxSub(es *caep.EventSubject) ctx.Sub {
	return NewCtxSubFromEventSubject(es)
}

func (tr *iCtxDB) EventSubject(sub ctx.Sub) (*caep.EventSubject, error) {
	ret := &caep.EventSubject{
		User: map[string]string{
			"format": "opaque",
			"opaque": sub.Options()["sub"],
		},
	}

	if d, ok := sub.Options()["dev"]; ok {
		ret.Device = map[string]string{"format": "opaque", "opaque": d}
	}
	return ret, nil
}
func (tr *iCtxDB) CtxID(sub ctx.Sub, ct ctx.Type) (ctx.ID, error) {
	var c c
	b, err := tr.r.Load(tr.key(sub, ct))
	if err != nil {
		return nil, fmt.Errorf("tr.CtxID(%v,%v) はないよ %v", sub, ct, err)
	}
	buf := bytes.NewBuffer(b)
	if err := gob.NewDecoder(buf).Decode(&c); err != nil {
		return nil, fmt.Errorf("tr.CtxID(%v,%v) のデコードに失敗 %v", sub, ct, err)
	}
	if c.id != "" {
		return c.ID(), nil
	}
	return nil, fmt.Errorf("まだ sub(%v) の ct(%V) には CtxID は設定されていない", sub, ct)
}
func (tr *iCtxDB) BindCtxIDToCtx(ctxID ctx.ID, sub ctx.Sub, ct ctx.Type) error {
	v, ok := tr.ctxBase.Load(ct.String())
	if !ok {
		return fmt.Errorf("event(%v) の type が対応していないため保存できない")
	}
	scopes := v.([]string)

	var prevCtx c
	// 以前に登録したものがあるか
	if b, err := tr.r.Load(tr.key(sub, ct)); err == nil {
		buf := bytes.NewBuffer(b)
		if err := gob.NewDecoder(buf).Decode(&prevCtx); err != nil {
			return fmt.Errorf("db.r.Load in BindCtxIDToCtx(%v,%v,%v) で失敗 %v", ctxID, sub, ct, err)
		}
	} else {
		prevCtx = c{
			scopes: scopes,
		}
	}

	c := newCtxFromCtxID(ctxID, sub, ct, &prevCtx)
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(c); err != nil {
		return err
	}
	return tr.r.Save(tr.key(sub, ct), buf.Bytes())
}

type iUMADB struct {
	r           Repository
	keyModifier string
}

var _ rx.UMADB = &iUMADB{}

func (db *iUMADB) keyPT(sub ctx.Sub) string {
	return db.r.KeyPrefix() + ":" + db.keyModifier + ":permissionticket:" + sub.String()
}

func (db *iUMADB) keyRPT(sub ctx.Sub) string {
	return db.r.KeyPrefix() + ":" + db.keyModifier + ":rpt:" + sub.String()
}

func (db *iUMADB) SetPermissionTicket(sub ctx.Sub, ticket *uma.PermissionTicket) error {
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(ticket); err != nil {
		return nil
	}
	return db.r.Save(db.keyPT(sub), buf.Bytes())
}

func (db *iUMADB) LoadPermissionTicket(sub ctx.Sub) (*uma.PermissionTicket, error) {
	var pt uma.PermissionTicket
	b, err := db.r.Load(db.keyPT(sub))
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(b)
	if err := gob.NewDecoder(buf).Decode(&pt); err != nil {
		return nil, err
	}
	return &pt, err

}
func (db *iUMADB) SetRPT(sub ctx.Sub, tok *uma.RPT) error {
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(tok); err != nil {
		return nil
	}
	return db.r.Save(db.keyRPT(sub), buf.Bytes())
}
func (db *iUMADB) LoadRPT(sub ctx.Sub) (*uma.RPT, error) {
	var rpt uma.RPT
	b, err := db.r.Load(db.keyRPT(sub))
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(b)
	if err := gob.NewDecoder(buf).Decode(&rpt); err != nil {
		return nil, err
	}
	return &rpt, nil
}
