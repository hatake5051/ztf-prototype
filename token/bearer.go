package token

import (
	"errors"

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

type IDToken struct {
	Token
	RawIDToken string        `json:"id_token"`
	Claims     jwt.MapClaims `json:"-"`
}

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

func (tid *IDToken) Signed(claims *jwt.StandardClaims) error {
	idt := jwt.NewWithClaims(jwt.GetSigningMethod("none"), claims)
	idtokenStr, err := idt.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		return err
	}
	tid.RawIDToken = idtokenStr
	return nil
}
