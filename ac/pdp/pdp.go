package pdp

import (
	"github.com/hatake5051/ztf-prototype/ac"
	"github.com/hatake5051/ztf-prototype/ctx"
)

// PDP は認可判断の主体
type PDP interface {
	// NotifiedOfRequest は認可判断に必要なコンテキストはなにか PIP に伝える
	// すでに認証が終わり、どのユーザがどのリソースへ何のアクションを行いたいか理解している前提
	// この時点でアクセス拒否が明らかなら deny = true を返す
	NotifiedOfRequest(ac.Subject, ac.Resource, ac.Action) (reqctxs []ac.ReqContext, deny bool)
	// Decision は認可判断を行う
	// 認可判断の結果アクセスを許可するなら nil を返す
	Decision(ac.Subject, ac.Resource, ac.Action, []ctx.Ctx) error
}
