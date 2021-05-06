package pip

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"sync"

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

type smForSubPIPimpl struct {
	r           Repository
	keyModifier string
}

var _ smForSubPIP = &smForSubPIPimpl{}

func (sm *smForSubPIPimpl) key(session string) string {
	return sm.r.KeyPrefix() + ":" + sm.keyModifier + ":" + session
}

func (sm *smForSubPIPimpl) Load(session string) (*subIdentifier, error) {
	b, err := sm.r.Load(sm.key(session))
	if err != nil {
		return nil, err
	}
	var subID subIdentifier
	buf := bytes.NewBuffer(b)
	if err := gob.NewDecoder(buf).Decode(&subID); err != nil {
		return nil, err
	}
	return &subID, nil
}

func (sm *smForSubPIPimpl) Set(session string, subID *subIdentifier) error {
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(subID); err != nil {
		return nil
	}
	return sm.r.Save(sm.key(session), buf.Bytes())
}

type subDBimple struct {
	r           Repository
	keyModifier string
}

var _ subDB = &subDBimple{}

func (db *subDBimple) key(id *subIdentifier) string {
	return db.r.KeyPrefix() + ":" + db.keyModifier + ":" + id.Iss + ":" + id.Sub
}

func (db *subDBimple) Load(key *subIdentifier) (*subject, error) {
	var sub subject
	b, err := db.r.Load(db.key(key))
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(b)
	if err := gob.NewDecoder(buf).Decode(&sub); err != nil {
		return nil, err
	}
	return &sub, nil
}

func (db *subDBimple) Set(idt openid.Token) error {
	subID := newSubID(idt)
	sub := &subject{subID}
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(sub); err != nil {
		return nil
	}
	return db.r.Save(db.key(subID), buf.Bytes())
}

type smForCtxManagerimple struct {
	r           Repository
	keyModifier string
}

var _ smForCtxManager = &smForCtxManagerimple{}

func (sm *smForCtxManagerimple) key(session string) string {
	return sm.r.KeyPrefix() + ":" + sm.keyModifier + ":" + session
}

func (sm *smForCtxManagerimple) Load(session string) (*subForCtx, error) {
	var sub subForCtx
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

func (sm *smForCtxManagerimple) Set(session string, sub *subForCtx) error {
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(sub); err != nil {
		return err
	}
	return sm.r.Save(sm.key(session), buf.Bytes())
}

type ctxDBimple struct {
	r           Repository
	keyModifier string
}

var _ ctxDB = &ctxDBimple{}

func (db *ctxDBimple) key(sub *subForCtx, ct ctxType) string {
	return db.r.KeyPrefix() + ":" + db.keyModifier + ":sub:" + sub.Identifier() + ":ct:" + string(ct)
}

func (db *ctxDBimple) Load(sub *subForCtx, req []reqCtx) ([]ctx, error) {
	var ret []ctx
	for _, r := range req {
		var c ctx
		b, err := db.r.Load(db.key(sub, r.Type))
		if err != nil {
			continue
		}
		buf := bytes.NewBuffer(b)
		if err := gob.NewDecoder(buf).Decode(&c); err != nil {
			continue
		}
		ret = append(ret, c)
	}
	if len(ret) == 0 {
		return nil, fmt.Errorf("コンテキストがまだ集まっていない")
	}
	return ret, nil
}

func (db *ctxDBimple) UMAResID(sub *subForCtx, ct ctxType) (uma.ResID, error) {
	var c ctx
	b, err := db.r.Load(db.key(sub, ct))
	if err != nil {
		return "", fmt.Errorf("UMAResID %#v", err)
	}
	buf := bytes.NewBuffer(b)
	if err := gob.NewDecoder(buf).Decode(&c); err != nil {
		return "", err
	}
	return c.ResID, nil
}

func (db *ctxDBimple) Set(c *ctx) error {
	// 以前に登録したものがあるか
	b, err := db.r.Load(db.key(c.Sub, c.Type))
	if err == nil {
		var prevCtx ctx
		buf := bytes.NewBuffer(b)
		if err := gob.NewDecoder(buf).Decode(&prevCtx); err == nil {
			// あれば新しく来たものだけ更新する
			for scopeKey, value := range prevCtx.ScopeValues {
				_, ok := c.ScopeValues[scopeKey]
				if !ok {
					c.ScopeValues[scopeKey] = value
				}
			}
		}
	}

	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(c); err != nil {
		return err
	}
	return db.r.Save(db.key(c.Sub, c.Type), buf.Bytes())
}

type umaClientDBimpl struct {
	r           Repository
	keyModifier string
}

var _ umaClientDB = &umaClientDBimpl{}

func (db *umaClientDBimpl) keyPT(sub *subForCtx) string {
	return db.r.KeyPrefix() + ":" + db.keyModifier + ":permissionticket:" + sub.Identifier()
}

func (db *umaClientDBimpl) keyRPT(sub *subForCtx) string {
	return db.r.KeyPrefix() + ":" + db.keyModifier + ":rpt:" + sub.Identifier()
}

func (db *umaClientDBimpl) SetPermissionTicket(sub *subForCtx, ticket *uma.PermissionTicket) error {
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(ticket); err != nil {
		return nil
	}
	return db.r.Save(db.keyPT(sub), buf.Bytes())
}

func (db *umaClientDBimpl) LoadPermissionTicket(sub *subForCtx) (*uma.PermissionTicket, error) {
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
func (db *umaClientDBimpl) SetRPT(sub *subForCtx, tok *uma.RPT) error {
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(tok); err != nil {
		return nil
	}
	return db.r.Save(db.keyRPT(sub), buf.Bytes())
}
func (db *umaClientDBimpl) LoadRPT(sub *subForCtx) (*uma.RPT, error) {
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
