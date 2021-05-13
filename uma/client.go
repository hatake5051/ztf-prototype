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
	AuthZSrv *url.URL
	//  ClientCred は認可サーバにアクセスする際のクレデンシャルである
	ClientCred struct {
		ID     string
		Secret string
	}
}

// New は設定情報をもとにUMAクライアントを構築する
// 認可サーバの情報の取得に失敗するとパニック
func (c *ClientConf) New(db ClientStore) Client {
	authZSrvConf, err := NewAuthZSrvConf(c.AuthZSrv)
	if err != nil {
		panic(fmt.Sprintf("uma.Client の構成に失敗(認可サーバの設定を取得できなかった) err: %v", err))
	}

	conf := &cliConf{
		id:       c.ClientCred.ID,
		secret:   c.ClientCred.Secret,
		tokenURL: authZSrvConf.TokenURL,
	}
	return &cli{
		azconf: authZSrvConf,
		conf:   conf,
		db:     db,
	}
}

// Client はUMAクライアントを表す
type Client interface {
	// Client は RPT があればそれを付与した http.Client を、なければ http.DefaultClient を返す.
	// When http.DefaultClient, Resource Server Response to Client on Permission Request
	// targetID はアクセスするリソースをまとめて一つの識別子として考える。 targetID と RPT が一対一に対応する。
	Client(context context.Context, targetID string) *http.Client
	// ClientWithPT は Resrouce Server の permission request から、 RPT を取得するフローを始める。
	// RPT を獲得できればそれを付与した http.Client を、獲得できなかった場合は error を返す。
	// 特に、RPT 取得に失敗した場合の error は ReqRPTError の場合がある。
	// targetID はアクセスするリソースをまとめて一つの識別子として考える。 targetID と RPT が一対一に対応する。
	ClientWithPT(context context.Context, targetID, requestingPartyClaim string, resp *http.Response) (*http.Client, error)
}

// ClientStore は UMA Client が使う RPT の保存先
// targetID はアクセスするリソースをまとめて一つの識別子として考える。 targetID と RPT が一対一に対応する。
type ClientStore interface {
	LoadRPT(targetID string) (*RPT, error)
	SaveRPT(targetID string, rpt *RPT) error
}

type cliConf struct {
	id       string
	secret   string
	tokenURL string
}

type cli struct {
	azconf *AuthZSrvConf
	conf   *cliConf
	db     ClientStore
}

func (c *cli) Client(context context.Context, targetID string) *http.Client {
	if rpt, err := c.db.LoadRPT(targetID); err != nil {
		if !rpt.refreshExpired() {
			fmt.Printf("[UMA] RPT for the targetID is %#v\n", rpt)
			// clientcredentials.Config では refresh token retrieval を行わないため oauth2.config を用意
			oauthconfig := &oauth2.Config{
				ClientID:     c.conf.id,
				ClientSecret: c.conf.secret,
				Endpoint: oauth2.Endpoint{
					TokenURL: c.conf.tokenURL,
				},
			}
			return oauthconfig.Client(context, rpt.t)
		}
		fmt.Printf("[UMA] Redresh Token in RPT is expired %#v\n", rpt)
	}
	fmt.Printf("[UMA] Client.Client returns normal http.Client\n")
	return http.DefaultClient
}

func (c *cli) ClientWithPT(context context.Context, targetID, requestingPartyClaim string, ptResp *http.Response) (*http.Client, error) {
	pt, err := c.extractPermissionTicket(ptResp)
	if err != nil {
		return nil, fmt.Errorf("Cannot Parse as Permission Ticket %v", err)
	}
	rpt, err := c.reqRPT(context, pt, requestingPartyClaim)
	if err != nil {
		return nil, err
	}
	if err := c.db.SaveRPT(targetID, rpt); err != nil {
		return nil, fmt.Errorf("Cannot Saved rpt %w", err)
	}
	return c.Client(context, targetID), nil
}

// extractPermissionTicket はリソースサーバが応答した HTTP Response から
// Permission Ticket を抽出する
func (c *cli) extractPermissionTicket(resp *http.Response) (*PermissionTicket, error) {
	pt, err := initialPermissionTicket(resp)
	if err != nil {
		return nil, fmt.Errorf("fail to parse PT response %v\n", err)
	}
	if pt.InitialOption.AuthZSrv != c.azconf.Issuer {
		return nil, fmt.Errorf("sould be equeal Metadata Issuer: %v, resp: %v", c.azconf.Issuer, pt.InitialOption.AuthZSrv)
	}
	return pt, nil
}

// ReqRPT は認可サーバに RPT 要求を行う
func (c *cli) reqRPT(context context.Context, pt *PermissionTicket, requestingPartyClaim string) (*RPT, error) {
	oauthconfig := &clientcredentials.Config{
		ClientID:       c.conf.id,
		ClientSecret:   c.conf.secret,
		TokenURL:       c.conf.tokenURL,
		EndpointParams: requestParams(pt, requestingPartyClaim),
	}
	tok, err := oauthconfig.Token(context)
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
	var rpt *RPT
	rpt.new(tok)
	return rpt, nil
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

func requestParams(pt *PermissionTicket, requestingPartyClaim string) url.Values {
	umaReqs := url.Values{}
	umaReqs.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	umaReqs.Set("ticket", pt.Ticket)
	umaReqs.Set("claim_token", requestingPartyClaim)
	umaReqs.Set("claim_token_format", "http://openid.net/specs/openid-connect-core-1_0.html#IDToken")
	return umaReqs
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
