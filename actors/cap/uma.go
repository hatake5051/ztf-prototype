package cap

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/hatake5051/ztf-prototype/uma"
)

// UMAResSrv で使うセッションを管理する sessionStore
type SessionStoreForUMAResSrv interface {
	// IdentifySubject は今現在アクセスしてきているサブジェクトの識別子を返す
	IdentifySubject(r *http.Request) (SubAtCAP, error)
	// LoadRedirectBack はセッションに紐づいて保存しておいたリダイレクトURLを返す
	LoadRedirectBack(r *http.Request) (redirectURL string)
	// SetRedirectBack はセッションに次進むべきURLを保存する
	SetRedirectBack(r *http.Request, w http.ResponseWriter, redirectURL string) error
}

// UMAResSrv で使うコンテキストデータベース
type CtxDBForUMAResSrv interface {
	// Load は Sub と ctx を指定してそのコンテキストを受け取る
	Load(SubAtCAP, ctxType) (*ctx, error)
	// SaveIDAtAuthZSrv は認可サーバが発行したリソースIDをコンテキストに紐づけて保存する
	SaveIDAtAuthZSrv(SubAtCAP, ctxType, uma.ResID) error
}

// newUMASrv は CAP における UMA リソースサーバ としての機能を提供する UMAResSrv を返す
func newUMASrv(u uma.ResSrv, ctxDB CtxDBForUMAResSrv, store SessionStoreForUMAResSrv) UMAResSrv {
	return &umasrv{
		uma:   u,
		ctxDB: ctxDB,
		store: store,
	}
}

// UMASrv は UMA ProtectionAPI のリソース登録エンドポイントへのアクセスを行う
type UMAResSrv interface {
	// CRUD はアクセスしてきたユーザのコンテキストを認可サーバに登録したりする
	CRUD(w http.ResponseWriter, r *http.Request)
	// List はアクセスしてきたユーザの、認可サーバに登録してあるリソース一覧を返す
	List(w http.ResponseWriter, r *http.Request)
	// CallBack は PAT 取得する際のリダイレクトバック先
	CallBack(w http.ResponseWriter, r *http.Request)
}

// UMAResSrv の実装
type umasrv struct {
	uma   uma.ResSrv
	store SessionStoreForUMAResSrv
	ctxDB CtxDBForUMAResSrv
}

func (u *umasrv) CallBack(w http.ResponseWriter, r *http.Request) {
	sub, err := u.store.IdentifySubject(r)
	if err != nil {
		http.Error(w, "ユーザを識別できません", http.StatusUnauthorized)
		return
	}

	if err := u.uma.CallbackForPAT(uma.SubAtResSrv(sub), r); err != nil {
		http.Error(w, fmt.Sprintf("failed to exchange pat(owned: %s) %#v", sub, err), http.StatusInternalServerError)
		return
	}

	redirectURL := u.store.LoadRedirectBack(r)
	http.Redirect(w, r, redirectURL, http.StatusFound)
	return
}

func (u *umasrv) List(w http.ResponseWriter, r *http.Request) {
	sub, err := u.store.IdentifySubject(r)
	if err != nil {
		http.Error(w, "ユーザを識別できません", http.StatusUnauthorized)
		return
	}
	resList, err := u.uma.List(uma.SubAtResSrv(sub))
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
	s := "<html><head/><body><h1>登録済みコンテキスト一覧(認可サーバにおけるID一覧)</h1>"
	s += "<ul>"
	for _, resID := range resList {
		s += fmt.Sprintf("<li>%s</li>", resID)
	}
	s += "</ul></body></html>"
	w.Write([]byte(s))
	return
}

func (u *umasrv) CRUD(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("CRUD\n")
	sub, err := u.store.IdentifySubject(r)
	if err != nil {
		http.Error(w, "ユーザを識別できません", http.StatusUnauthorized)
		return
	}

	// どのコンテキストを操作するか Query から読み取る
	ct := r.FormValue("t")
	// 今アクセスしているユーザのそのコンテキストの中身を取得する
	ctx, err := u.ctxDB.Load(sub, ctxType(ct))
	if err != nil {
		http.Error(w, fmt.Sprintf("ctxType(%s) のコンテキストは管理していません", ct), http.StatusBadRequest)
		return
	}
	var res *uma.Res
	method := r.FormValue("m")
	if method == "" {
		method = r.Method
	}

	fmt.Printf("CRUD(%s) %#v\n", method, ctx)
	if method == http.MethodPost {
		var scopes []string
		for _, s := range ctx.Scopes {
			scopes = append(scopes, string(s))
		}
		res = &uma.Res{
			Name:   ctx.Name,
			Scopes: scopes,
			Type:   ctx.Type.UMAResType(),
		}
	} else {
		res = &uma.Res{
			ID: ctx.IDAtAuthZSrv,
		}
	}

	newres, err := u.uma.CRUD(uma.SubAtResSrv(sub), method, res)
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
		if err := u.ctxDB.SaveIDAtAuthZSrv(sub, ctxType(ct), newres.ID); err != nil {
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
