package token

import (
	jwt "github.com/dgrijalva/jwt-go"
)

type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

func (t *Token) String() string {
	return t.TokenType + " " + t.AccessToken
}

type TokenWithID struct {
	Token
	IDToken string `json:"id_token"`
}

func (tid *TokenWithID) ParseIDToken() (*jwt.Token, error) {
	t, err := jwt.Parse(tid.IDToken, func(t *jwt.Token) (interface{}, error) {
		b := jwt.UnsafeAllowNoneSignatureType
		return b, nil
	})
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (tid *TokenWithID) Signed(claims *jwt.StandardClaims) error {
	idt := jwt.NewWithClaims(jwt.GetSigningMethod("none"), claims)
	idtokenStr, err := idt.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		return err
	}
	tid.IDToken = idtokenStr
	return nil
}
