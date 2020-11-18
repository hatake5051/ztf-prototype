package uma

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

// ClientConf はUMAクライアントの設定情報を表す
type ClientConf struct {
	AuthZSrv string
}

// New は設定情報をもとにUMAクライアントを構築する
// 認可サーバの情報の取得に失敗するとパニック
// setAuthHeader はRPT要求をする際に Authorization Header を付与する関数
func (c *ClientConf) New(setAuthHeader func(r *http.Request)) Client {
	authZSrv, err := NewAuthZSrv(c.AuthZSrv)
	if err != nil {
		panic(fmt.Sprintf("uma.Client の構成に失敗(認可サーバの設定を取得できなかった) err: %v", err))
	}
	return &cli{
		authZ:      authZSrv,
		authHeader: setAuthHeader,
	}
}

// Client はUMAクライアントを表す
type Client interface {
	ParsePTAndReqRPT(resp *http.Response) (*RPT, error)
	ReqRPT(pt *PermissionTicket) (*RPT, error)
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
	authZ      *AuthZSrv
	authHeader func(r *http.Request)
}

func (c *cli) ParsePTAndReqRPT(resp *http.Response) (*RPT, error) {
	pt, err := InitialPermissionTicket(resp)
	if err != nil {
		return nil, err
	}
	return c.ReqRPT(pt)
}

func (c *cli) ReqRPT(pt *PermissionTicket) (*RPT, error) {

	if pt.InitialOption != nil && c.authZ.Issuer != pt.InitialOption.AuthZSrv {
		return nil, fmt.Errorf("この許可チケットの発行者に対するクライアントではない")
	}
	return ReqRPT(c.authZ.TokenURL, pt.Ticket, c.authHeader)
}

// InitialPermissionTicket は resp から PermissionTicket を抽出する
func InitialPermissionTicket(resp *http.Response) (*PermissionTicket, error) {
	if resp.StatusCode != http.StatusUnauthorized {
		return nil, fmt.Errorf("status code unmatched: expected 403 but %v", resp.StatusCode)
	}
	wwwAuthn := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(wwwAuthn, "UMA") {
		return nil, fmt.Errorf("WWW-Authenticated Header should start with UMA")
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

// ReqRPT は PermissionTicket をもとに RPT を認可サーバに要求する
// setAuthHeader は認可サーバのトークンエンドポイントにアクセスするための認可情報をリクエストに付与する
func ReqRPT(tokenURL, ticket string, setAuthHeader func(r *http.Request)) (*RPT, error) {
	// HTTP Requrst の準備
	body := url.Values{}
	body.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	body.Add("ticket", ticket)
	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setAuthHeader(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	if contentType != "application/json" {
		return nil, fmt.Errorf("contentType(%v) is not matched with app/json", contentType)
	}
	if resp.StatusCode != http.StatusOK {
		ee := new(ReqRPTError)
		if err := json.NewDecoder(resp.Body).Decode(ee); err != nil {
			return nil, err
		}
		return nil, ee
	}
	t := new(RPT)
	if err := json.NewDecoder(resp.Body).Decode(t); err != nil {
		return nil, err
	}
	return t, nil
}
