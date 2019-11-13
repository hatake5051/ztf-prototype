package token

import (
	"errors"

	jwt "github.com/dgrijalva/jwt-go"
)

// Token は Oauth2.0 Provider が発行するアクセストークン
type Token struct {
	// Token 識別子
	AccessToken string `json:"access_token"`
	// Bearer のみサポートしている
	TokenType string `json:"token_type"`
	// 与えられる権限
	Scope string `json:"scope"`
}

// SetAuthorizationHeader Bearer トークンは Authorization Header につけて送信する
func (t *Token) SetAuthorizationHeader() string {
	return t.TokenType + " " + t.AccessToken
}

// IDToken は OIDC Provider が発行するIDトークン
type IDToken struct {
	// UserInfo エンドポイントにアクセスする際に用いる
	Token
	// JWT 形式にシリアライズされたIDトークン
	RawIDToken string `json:"id_token"`
	// IDトークン内の情報
	Claims jwt.MapClaims `json:"-"`
}

// ParseIDToken は IDToken をパースし、JWT署名の検証に成功すると、Claims を有効にする
func (tid *IDToken) ParseIDToken() error {
	t, err := jwt.Parse(tid.RawIDToken, func(t *jwt.Token) (interface{}, error) {
		b := jwt.UnsafeAllowNoneSignatureType
		return b, nil
	})
	if err != nil {
		return err
	}
	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("IdToken claims is not jwt.MapClaims")
	}
	tid.Claims = claims
	return nil
}

// Signed は 引数の claims に署名をし、有効なIDTokenへと変化させる
func (tid *IDToken) Signed(claims jwt.MapClaims) error {
	idt := jwt.NewWithClaims(jwt.GetSigningMethod("none"), claims)
	idtokenStr, err := idt.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		return err
	}
	tid.RawIDToken = idtokenStr
	tid.Claims = claims
	return nil
}
