package cap

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/sessions"
	"github.com/hatake5051/ztf-prototype/uma"
)

func newUMASrv(u uma.ResSrv, ctxs map[string][]string, store sessions.Store) (UMASrv, resDB) {
	db := &umaDB{
		onces: make(map[string]*sync.Once),
		uma:   u,
		db1:   make(map[string][]string),
		db2:   make(map[string]uma.Res),
	}
	return &umasrv{
		ctxs,
		store,
		db,
		u,
	}, db
}

// UMASrv は UMA ProtectionAPI のリソース登録エンドポイントへのアクセスを行う
type UMASrv interface {
	CRUD(w http.ResponseWriter, r *http.Request)
}

type umasrv struct {
	ctxs  map[string][]string // ctxID -> scopes
	store sessions.Store
	db    *umaDB
	uma   uma.ResSrv
}

func (u *umasrv) CRUD(w http.ResponseWriter, r *http.Request) {
	session, err := u.store.Get(r, "UMA_PROTECTION_API_AUTHN")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sub, ok := session.Values["subject"].(string)
	name, ok := session.Values["name"].(string)
	if !ok {
		http.Error(w, "認証MWを潜り抜けている！！", http.StatusForbidden)
		return
	}

	ctxID := r.FormValue("id")
	var res *uma.Res
	if r.Method == http.MethodPost {
		for cid, scopes := range u.ctxs {
			if cid == ctxID {
				res = &uma.Res{
					Name:   resName(name, ctxID),
					Owner:  sub,
					Scopes: scopes,
				}
				break
			}
		}
	} else {
		res, err = u.db.Load(sub, ctxID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if res == nil {
		http.Error(w, fmt.Sprintf("クエリが正しくないよ request: %#v", r), http.StatusBadRequest)
		return
	}
	newres, err := u.uma.CRUD(r.Method, res)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := u.db.Save(sub, newres); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s := "<html><head/><body><h1>コンテキスト詳細</h1>"
	s += "<ul>"
	s += "<li>ID: " + res.ID + "</li>"
	s += "<li>Name: " + res.Name + "</li>"
	s += "<li>Owner: " + res.Owner + "</li>"
	s += fmt.Sprintf("<li>%s: %t</li>", "OwnerManagedAccess", res.OwnerManagedAccess)
	s += fmt.Sprintf("<li>%s: %s</li>", "Scopes", strings.Join(res.Scopes, " "))
	s += "</ul>"
	s += `<a href="/auth/list">一覧に戻る</a>`
	s += "</body></html>"
	// んー、<> をエスケープしない
	w.Write([]byte(s))
}

type resDB interface {
	Load(spagID, ctxID string) (*uma.Res, error)
}

type umaDB struct {
	m2    sync.Mutex
	onces map[string]*sync.Once // spagID -> once
	uma   uma.ResSrv
	m1    sync.RWMutex
	db1   map[string][]string // spagID -> [resID]
	db2   map[string]uma.Res  // resID -> Res
}

func (db *umaDB) Load(spagID, ctxID string) (*uma.Res, error) {
	db.m2.Lock()
	once, ok := db.onces[spagID]
	if !ok {
		once = &sync.Once{}
		db.onces[spagID] = once
	}
	once.Do(func() {
		resIDs, err := db.uma.List(spagID)
		if err != nil {
			fmt.Printf("spagID(%s) の登録済みリソース一覧に取得に失敗 %v\n", spagID, err)
			return
		}
		db.m1.Lock()
		db.db1[spagID] = resIDs
		for _, rid := range resIDs {
			res, err := db.uma.CRUD("GET", &uma.Res{ID: rid})
			if err != nil {
				fmt.Printf("spagID(%s) の resID(%s) の詳細取得に失敗 %v\n", spagID, rid, err)
				continue
			}
			db.db2[rid] = *res
		}
		db.m1.Unlock()
	})
	db.m2.Unlock()
	db.m1.RLock()
	defer db.m1.RUnlock()
	resIDs, ok := db.db1[spagID]
	if !ok || resIDs == nil {
		return nil, fmt.Errorf("spagID(%s) はリソースを一つも持っていない", spagID)
	}
	for _, rid := range resIDs {
		res, ok := db.db2[rid]
		if ok && strings.Contains(res.Name, ctxID) {
			return &res, nil
		}
	}
	return nil, fmt.Errorf("spagID(%s) は ctxID(%s) のリソースを持っていない", spagID, ctxID)
}

func (db *umaDB) Save(spagID string, res *uma.Res) error {
	db.m1.Lock()
	defer db.m1.Unlock()
	db.db1[spagID] = append(db.db1[spagID], res.ID)
	db.db2[res.ID] = *res
	return nil
}

func resName(name, ctxID string) string {
	return fmt.Sprintf("sub:%s:ctx:%s", name, ctxID)
}
