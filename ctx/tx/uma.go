package tx

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/hatake5051/ztf-prototype/ctx"
	"github.com/hatake5051/ztf-prototype/uma"
)

func (conf *UMAConf) new(store SessionStoreForUMA, ctxDB CtxDBForUMA, trans TranslaterForUMA) *umaResSrv {
	return &umaResSrv{conf.to().New(&iPATClientStore{}), store, ctxDB, trans}
}

// umaResSrv は UMA ProtectionAPI のリソース登録エンドポイントへのアクセスを行う
type umaResSrv struct {
	uma   uma.ResSrv
	store SessionStoreForUMA
	ctxDB CtxDBForUMA
	trans TranslaterForUMA
}

func (u *umaResSrv) permissionTicket(context context.Context, ctxReqs []struct {
	id     ctx.ID
	scopes []ctx.Scope
}) error {
	// RPT トークンがない -> UMA Grant Flow を始める
	var reqs []uma.ResReqForPT
	for _, creq := range ctxReqs {
		req, err := u.trans.ResReq(creq.id, creq.scopes)
		if err != nil {
			fmt.Printf("AddSub で EventID -> ResID の変換に失敗 %v\n", err)
			return fmt.Errorf("AddSub で EventID -> ResID の変換に失敗 %v\n", err)
		}
		reqs = append(reqs, req)
	}
	pt, err := u.uma.PermissionTicket(context, reqs)
	if err != nil {
		return err
	}
	s := fmt.Sprintf(`UMA realm="%s",as_uri="%s",ticket="%s"`, pt.InitialOption.ResSrv, pt.InitialOption.AuthZSrv, pt.Ticket)
	m := map[string]string{"WWW-Authenticate": s}
	return newTrEO(fmt.Errorf("UMA NoRPT"), caep.TxErrorUnAuthorized, m)
}

// CallBack は PAT 取得する際のリダイレクトバック先
func (u *umaResSrv) callBack(w http.ResponseWriter, r *http.Request) {
	sub, err := u.store.IdentifySubject(r)
	if err != nil {
		http.Error(w, "ユーザを識別できません", http.StatusUnauthorized)
		return
	}

	if err := u.uma.CallbackForPAT(sub.UMAResSrv(), r); err != nil {
		http.Error(w, fmt.Sprintf("failed to exchange pat(owned: %s) %#v", sub, err), http.StatusInternalServerError)
		return
	}

	redirectURL := u.store.LoadAndDeleteRedirectBack(r)
	http.Redirect(w, r, redirectURL, http.StatusFound)
	return
}

// List はアクセスしてきたユーザの、認可サーバに登録してあるリソース一覧を返す
func (u *umaResSrv) list(w http.ResponseWriter, r *http.Request) {
	sub, err := u.store.IdentifySubject(r)
	if err != nil {
		http.Error(w, "ユーザを識別できません", http.StatusUnauthorized)
		return
	}

	// POST の場合は、認可サーバに登録してあったリソースを確認し、Tx 内の ctx と res の結びつけを再度行う
	// CAP などが再起動してメモリ情報が失われた時ように用意している
	if r.Method == http.MethodPost {
		resList, err := u.uma.List(r.Context(), sub.UMAResSrv())
		if err != nil {
			if err, ok := err.(*uma.ProtectionAPIError); ok {
				if err.Code == uma.ProtectionAPICodeUnAuthorized {
					if err := u.store.SetRedirectBack(r, w, r.URL.String()); err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					http.Redirect(w, r, err.Description, http.StatusFound)
					return
				}
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, resID := range resList {
			res, err := u.uma.CRUD(r.Context(), sub.UMAResSrv(), http.MethodGet, &uma.Res{ID: uma.ResID(resID)})
			if err != nil {
				fmt.Printf("uma.GET(%v,%v) に失敗 %v\n", sub, resID, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if err := u.trans.ReBindRes(res); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}

	ctxs, err := u.ctxDB.LoadAllOfSub(sub)
	if err != nil {
		http.Error(w, "u.ctxDB.LoadAll(sub) に失敗 "+err.Error(), http.StatusInternalServerError)
		return
	}

	s := fmt.Sprintf("<html><head/><body><h1>%s さんのコンテキスト一覧</h1>", sub.PreferredName())
	for _, c := range ctxs {
		s += fmt.Sprintf("<h2> Context Type: %s</h2>", c.Type().String())
		s += "<ul>"
		s += fmt.Sprintf("<li>ID: %s</li>", c.ID().String())

		s += "<li>"
		if _, err := u.trans.Res(c); err != nil {
			s += ` <form action="ctx" method="POST">`
			s += fmt.Sprintf(`<input type="hidden" name="t" value="%s"> `, c.Type().String())
			s += `<button type="submit">認可サーバで保護する</button></form>`
		} else {
			s += ` <form action="ctx" method="GET">`
			s += fmt.Sprintf(`<input type="hidden" name="t" value="%s"> `, c.Type().String())
			s += `<button type="submit">詳細</button></form>`
		}
		s += "</li>"
		s += "</ul>"
	}
	s += `<h2>認可サーバとの同期</h2>`
	s += fmt.Sprintf(`<form method="POST"><button type="submit">認可サーバと同期する</button></form>`)
	s += "</body></html>"
	w.Write([]byte(s))
	return
}

// CRUD はアクセスしてきたユーザのコンテキストを認可サーバに登録したりする
func (u *umaResSrv) crud(w http.ResponseWriter, r *http.Request) {
	sub, err := u.store.IdentifySubject(r)
	if err != nil {
		http.Error(w, "ユーザを識別できません", http.StatusUnauthorized)
		return
	}

	// どのコンテキストを操作するか Query から読みとり、
	rawCtxType := r.FormValue("t")
	// 今アクセスしているユーザのそのコンテキストの中身を取得する
	c, err := u.ctxDB.LoadCtxOfSub(sub, ctx.NewCtxType(rawCtxType))
	if err != nil {
		http.Error(w, fmt.Sprintf("subtx (%v) の ctxType(%s) のコンテキストは管理していません", sub, rawCtxType), http.StatusBadRequest)
		return
	}
	var res *uma.Res
	// method は Query にあるであろう m を優先、なければ http.Method を使う
	method := r.FormValue("m")
	if method == "" {
		method = r.Method
	}

	fmt.Printf("CRUD(%s) %#v\n", method, c)

	res, err = u.trans.Res(c)
	if err != nil {
		http.Error(w, fmt.Sprintf("u.trans.Res(%#v) failed because %v", c, err), http.StatusInternalServerError)
		return
	}

	newres, err := u.uma.CRUD(r.Context(), sub.UMAResSrv(), method, res)
	if err != nil {
		if err, ok := err.(*uma.ProtectionAPIError); ok {
			if err.Code == uma.ProtectionAPICodeUnAuthorized {
				ur, _ := url.Parse(r.URL.String())
				q := ur.Query()
				q.Set("m", r.Method)
				q.Set("t", rawCtxType)
				ur.RawQuery = q.Encode()

				fmt.Printf("url %s\n", ur.String())
				if err := u.store.SetRedirectBack(r, w, ur.String()); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				http.Redirect(w, r, err.Description, http.StatusFound)
				return
			}
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Printf("new res %#v\n", newres)
	if method == http.MethodPost {
		if err := u.trans.BindResToCtx(newres, c); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	s := "<html><head/><body><h1>コンテキスト詳細</h1>"
	s += "<ul>"
	s += "<li>ID: " + string(newres.ID) + "</li>"
	s += "<li>Name: " + newres.Name + "</li>"
	s += "<li>Owner: " + string(newres.Owner) + "</li>"
	s += fmt.Sprintf("<li>%s: %t</li>", "OwnerManagedAccess", newres.OwnerManagedAccess)
	s += fmt.Sprintf("<li>%s: %s</li>", "Scopes", strings.Join(newres.Scopes, " "))
	s += "</ul>"
	s += `<a href="list">一覧に戻る</a>`
	s += "</body></html>"
	w.Write([]byte(s))
}

// ressrvDB は UMAリソースサーバ として機能する際の uma.ResSrvDB を実装する
type iPATClientStore struct {
	// // patdb は SubAtResSrv をキーとして PAT を保存する
	patdb sync.Map
	// // statedb は OAuth2.0 state をキーとして SubAtResSrv を保存数r
	statedb sync.Map
}

var _ uma.PATClientStore = &iPATClientStore{}

func (db *iPATClientStore) LoadPAT(sub uma.SubAtResSrv) (*uma.PAT, error) {
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

func (db *iPATClientStore) SavePAT(sub uma.SubAtResSrv, pat *uma.PAT) error {
	db.patdb.Store(string(sub), pat)
	return nil
}

func (db *iPATClientStore) LoadPATOfResSrv() (*uma.PAT, error) {
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

func (db *iPATClientStore) SavePATOfResSrv(pat *uma.PAT) error {
	db.patdb.Store("", pat)
	return nil
}

func (db *iPATClientStore) InitAndSaveState(sub uma.SubAtResSrv) string {
	// // state をランダムに生成する
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "methakutya-random"
	}
	state := base64.URLEncoding.EncodeToString(b)
	db.statedb.Store(state, sub)
	return state
}

func (db *iPATClientStore) LoadAndDeleteState(state string) (uma.SubAtResSrv, error) {
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
