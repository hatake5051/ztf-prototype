package token

type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

func (t *Token) String() string {
	return t.TokenType + " " + t.AccessToken
}
