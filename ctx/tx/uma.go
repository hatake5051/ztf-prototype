package tx

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/hatake5051/ztf-prototype/ctx"
	"github.com/hatake5051/ztf-prototype/uma"
)

// UMAResSrv で使うセッションを管理する sessionStore
type SessionStore interface {
	// IdentifySubject は今現在アクセスしてきているサブジェクトの識別子を返す
	IdentifySubject(r *http.Request) (ctx.Sub, error)
	// LoadRedirectBack はセッションに紐づいて保存しておいたリダイレクトURLを返す
	LoadRedirectBack(r *http.Request) (redirectURL string)
	// SetRedirectBack はセッションに次進むべきURLを保存する
	SetRedirectBack(r *http.Request, w http.ResponseWriter, redirectURL string) error
}

// umaResSrv は UMA ProtectionAPI のリソース登録エンドポイントへのアクセスを行う
type umaResSrv struct {
	uma   uma.ResSrv
	store SessionStore
	ctxDB CtxDB
	trans Translater
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

	redirectURL := u.store.LoadRedirectBack(r)
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
	// resList, err := u.uma.List(sub.UMAResSrv())
	// if err != nil {
	// 	if err, ok := err.(*uma.ProtectionAPIError); ok {
	// 		if err.Code == uma.ProtectionAPICodeUnAuthorized {
	// 			if err := u.store.SetRedirectBack(r, w, r.URL.String()); err != nil {
	// 				http.Error(w, err.Error(), http.StatusInternalServerError)
	// 				return
	// 			}
	// 			http.Redirect(w, r, err.Description, http.StatusFound)
	// 			return
	// 		}
	// 	}
	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
	// 	return
	// }

	ctxs, err := u.ctxDB.LoadAll(sub)
	if err != nil {
		http.Error(w, "u.ctxDB.LoadAll(sub) に失敗 "+err.Error(), http.StatusInternalServerError)
		return
	}

	s := fmt.Sprintf("<html><head/><body><h1>%s さんのコンテキスト一覧</h1>", sub.String())
	s += "<ul>"
	for _, c := range ctxs {
		s += fmt.Sprintf("<li>t: %s  ID: %s</li>", c.Type().String(), c.ID().String())
	}
	s += "</ul></body></html>"
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

	// どのコンテキストを操作するか Query から読み取る
	ct := r.FormValue("t")
	// 今アクセスしているユーザのそのコンテキストの中身を取得する
	c, err := u.ctxDB.Load(sub, ctx.NewCtxType(ct))
	if err != nil {
		http.Error(w, fmt.Sprintf("ctxType(%s) のコンテキストは管理していません", ct), http.StatusBadRequest)
		return
	}
	var res *uma.Res
	method := r.FormValue("m")
	if method == "" {
		method = r.Method
	}

	fmt.Printf("CRUD(%s) %#v\n", method, c)
	if method == http.MethodPost {
		var scopes []string
		for _, cs := range c.Scopes() {
			scopes = append(scopes, cs.String())
		}
		res = &uma.Res{
			Name:   c.Name(),
			Scopes: scopes,
			Type:   c.Type().UMAResType(),
		}
	} else {
		resID, err := u.trans.ResID(c.ID())
		if err != nil {
			http.Error(w, fmt.Sprintf("u.trans.ResID(%v) in umaResSrv.CRUD(POST) でエラー %v", c, err), http.StatusInternalServerError)
			return
		}
		res = &uma.Res{
			ID: resID,
		}
	}

	newres, err := u.uma.CRUD(sub.UMAResSrv(), method, res)
	if err != nil {
		if err, ok := err.(*uma.ProtectionAPIError); ok {
			if err.Code == uma.ProtectionAPICodeUnAuthorized {
				ur, _ := url.Parse(r.URL.String())
				q := ur.Query()
				q.Add("m", r.Method)
				q.Add("t", ct)
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
		if err := u.trans.BindResIDToSub(newres.ID, sub, ctx.NewCtxType(ct)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	s := "<html><head/><body><h1>コンテキスト詳細</h1>"
	s += "<ul>"
	s += "<li>ID: " + string(res.ID) + "</li>"
	s += "<li>Name: " + res.Name + "</li>"
	s += "<li>Owner: " + string(res.Owner) + "</li>"
	s += fmt.Sprintf("<li>%s: %t</li>", "OwnerManagedAccess", res.OwnerManagedAccess)
	s += fmt.Sprintf("<li>%s: %s</li>", "Scopes", strings.Join(res.Scopes, " "))
	s += "</ul>"
	s += `<a href="/list">一覧に戻る</a>`
	s += "</body></html>"
	// んー、<> をエスケープしない
	w.Write([]byte(s))
}

// ressrvDB は UMAリソースサーバ として機能する際の uma.ResSrvDB を実装する
type ressrvDB struct {
	// // patdb は SubAtResSrv をキーとして PAT を保存する
	patdb sync.Map
	// // statedb は OAuth2.0 state をキーとして SubAtResSrv を保存数r
	statedb sync.Map
}

var _ uma.ResSrvDB = &ressrvDB{}

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
