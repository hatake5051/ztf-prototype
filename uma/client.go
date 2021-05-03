package uma

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// ClientConf はUMAクライアントの設定情報を表す
type ClientConf struct {
	// AuthZSrv は認可サーバの URL である
	AuthZSrv string
	//  ClientCred は認可サーバにアクセスする際のクレデンシャルである
	ClientCred struct {
		ID     string
		Secret string
	}
}

// New は設定情報をもとにUMAクライアントを構築する
// 認可サーバの情報の取得に失敗するとパニック
func (c *ClientConf) New() Client {
	authZSrv, err := NewAuthZSrv(c.AuthZSrv)
	if err != nil {
		panic(fmt.Sprintf("uma.Client の構成に失敗(認可サーバの設定を取得できなかった) err: %v", err))
	}

	umaReqs := url.Values{}
	umaReqs.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	umaReqs.Set("ticket", "should-be-replaced")
	umaReqs.Set("claim_token", "should-be-replaced")
	umaReqs.Set("claim_token_format", "http://openid.net/specs/openid-connect-core-1_0.html#IDToken")
	conf := clientcredentials.Config{
		ClientID:       c.ClientCred.ID,
		ClientSecret:   c.ClientCred.Secret,
		TokenURL:       authZSrv.TokenURL,
		EndpointParams: umaReqs,
	}
	return &cli{
		authZ: authZSrv,
		conf:  conf,
	}
}

// Client はUMAクライアントを表す
type Client interface {
	// ExtractPermissionTicket はリソースサーバが応答した HTTP Response から
	// Permission Ticket を抽出する
	ExtractPermissionTicket(resp *http.Response) (*PermissionTicket, error)
	// ReqRPT は認可サーバに RPT 要求を行う
	ReqRPT(pt *PermissionTicket, rawidToken string) (*RPT, error)
}

// ReqRPTError はRPT要求に失敗した時のエラーメッセージを表す
type ReqRPTError struct {
	Err            string `json:"error"`
	ErrDescription string `json:"error_description"`
	Ticket         string `json:"ticket"`
}

func (e *ReqRPTError) Error() string {
	return e.Err + ":" + e.ErrDescription
}

type cli struct {
	authZ *AuthZSrv
	conf  clientcredentials.Config
}

func (c *cli) ExtractPermissionTicket(resp *http.Response) (*PermissionTicket, error) {
	pt, err := initialPermissionTicket(resp)
	if err != nil {
		return nil, err
	}
	if pt.InitialOption.AuthZSrv != c.authZ.Issuer {
		return nil, fmt.Errorf("sould be equeal Metadata Issuer: %v, resp: %v", c.authZ.Issuer, pt.InitialOption.AuthZSrv)
	}
	return pt, nil
}

// config は RPT を認可サーバに要求する際のパラメータを設定する。
// ticket はリソースサーバ から応答された permission ticket を、
// rawIDToken は認可サーバが理解できる、RPの Identity を IDToken で表現したものを引数として与える
func (c *cli) config(ticket, rawIDToken string) *clientcredentials.Config {
	ret := c.conf
	newparams := url.Values{}
	for k, v := range ret.EndpointParams {
		switch k {
		case "ticket":
			newparams.Set(k, ticket)
		case "claim_token":
			newparams.Set(k, rawIDToken)
		default:
			newparams[k] = v
		}
	}
	ret.EndpointParams = newparams
	return &ret
}

func (c *cli) ReqRPT(pt *PermissionTicket, rawidToken string) (*RPT, error) {
	if pt.InitialOption != nil && c.authZ.Issuer != pt.InitialOption.AuthZSrv {
		return nil, fmt.Errorf("この許可チケットの発行者に対するクライアントではない")
	}
	tok, err := c.config(pt.Ticket, rawidToken).Token(context.Background())
	if err != nil {
		// Error 内容が UMA Grant Protocol におけるエラーであれば、エラーをその型に変換する
		if err, ok := err.(*oauth2.RetrieveError); ok {
			ee := new(ReqRPTError)
			if err := json.Unmarshal(err.Body, ee); err != nil {
				return nil, err
			}
			return nil, ee
		}
		return nil, err
	}
	// RPT を返す
	return &RPT{*tok}, nil
}

// initialPermissionTicket は resp から PermissionTicket を抽出する
func initialPermissionTicket(resp *http.Response) (*PermissionTicket, error) {
	if resp.StatusCode != http.StatusUnauthorized {
		return nil, fmt.Errorf("status code unmatched: expected 403 but %v", resp.StatusCode)
	}
	wwwAuthn := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(wwwAuthn, "UMA") {
		return nil, fmt.Errorf("WWW-Authenticated Header should start with UMA. %s", wwwAuthn)
	}
	params := make(map[string]string)
	for _, s := range strings.Split(wwwAuthn[3:], ",") {
		tmp := strings.Split(s, "=")
		if len(tmp) != 2 {
			return nil, fmt.Errorf("but UMA WWW-Authenticated Header :%s", wwwAuthn)
		}
		params[tmp[0]] = strings.ReplaceAll(tmp[1], "\"", "")
	}
	return NewPermissionTicket(params["ticket"], params["as_uri"], params["realms"]), nil
}
