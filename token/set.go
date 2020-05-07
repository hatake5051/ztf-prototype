package token

import (
	"errors"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

type SETClaims struct {
	jwt.StandardClaims
	Events map[string]interface{} `json:"events"`
}

func NewSETClaims(rawSET string) (*SETClaims, error) {
	t, err := jwt.ParseWithClaims(rawSET, &SETClaims{}, func(t *jwt.Token) (interface{}, error) {
		b := jwt.UnsafeAllowNoneSignatureType
		return b, nil
	})
	if err != nil {
		return nil, err
	}
	set, ok := t.Claims.(*SETClaims)
	if !ok {
		return nil, errors.New("SET claims is not SETCLaims")
	}
	return set, nil
}

func ExtractSETClaimsFrom(req *http.Request) (*SETClaims, error) {
	defer req.Body.Close()
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	contentType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	if contentType != "application/jwt" {
		return nil, fmt.Errorf("not supported Content-Type: %v", contentType)
	}
	return NewSETClaims(string(body))
}

func (s *SETClaims) SignedString() (string, error) {
	set := jwt.NewWithClaims(jwt.GetSigningMethod("none"), s)
	return set.SignedString(jwt.UnsafeAllowNoneSignatureType)
}

func (s *SETClaims) ExtractUpdatedCtxID() (ctxIDs map[string]bool) {
	ctxIDs = make(map[string]bool)
	for eventID, _ := range s.Events {
		if index := strings.Index(eventID, ":raw"); index != -1 {
			ctxIDs[eventID[:index]] = true
			continue
		}
		if index := strings.Index(eventID, ":predicate:"); index != -1 {
			ctxIDs[eventID[:index]] = true
			continue
		}
	}
	return
}
