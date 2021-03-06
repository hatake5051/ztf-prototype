package rp

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

// New は CAP とコンテキストを連携してアクセス制御を行うサービスを展開する RP を生成する
func New(ac func(string) AC) *mux.Router {
	rp := &rp{
		store: sessions.NewCookieStore([]byte("super-secret-key")),
	}
	r := mux.NewRouter()
	r.HandleFunc("/", rp.ServeHTTP)
	ac("auth").Protect(r)
	return r
}

type rp struct {
	store *sessions.CookieStore
}

func (rp *rp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "ようこそ！")
	return
}
