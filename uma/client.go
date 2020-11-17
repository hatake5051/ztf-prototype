package uma

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

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
	return &PermissionTicket{
		Ticket: params["ticket"],
		InitialOption: &struct {
			AuthZSrv string
			ResSrv   string
		}{params["as_uri"], params["realms"]},
	}, nil
}

// ReqRPT は PermissionTicket をもとに RPT を認可サーバに要求する
// setAuthHeader は認可サーバのトークンエンドポイントにアクセスするための認可情報をリクエストに付与する
func ReqRPT(tokenURL, ticket string, setAuthHeader func(r *http.Request)) (*RPT, error) {
	body := url.Values{}
	body.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	body.Add("ticket", ticket)
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setAuthHeader(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	if contentType != "application/json" {
		return nil, fmt.Errorf("contentType(%v) is not matched with app/json", contentType)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		e := new(e)
		if err := json.NewDecoder(resp.Body).Decode(e); err != nil {
			return nil, err
		}
		return nil, e
	} else {
		t := new(RPT)
		if err := json.NewDecoder(resp.Body).Decode(t); err != nil {
			return nil, err
		}
		return t, nil
	}
}

type Error interface {
	error
	Hint() string
}

type e struct {
	Err            string `json:"error"`
	ErrDescription string `json:"error_description"`
	Ticket         string `json:"ticket,omitempty"`
}

func (e *e) Error() string {
	return e.Err
}

func (e *e) Hint() string {
	return e.ErrDescription
}
