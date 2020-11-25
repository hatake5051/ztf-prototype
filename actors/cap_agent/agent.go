package cap_agent

import (
	"bytes"
	"fmt"
	"net/http"

	"github.com/hatake5051/ztf-prototype/caep"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

func Send() error {
	ev := &caep.SSEEventClaim{
		ID: "ctx-1",
		Subject: struct {
			SubType string "json:\"subject_type\""
			SpagID  string "json:\"spag_id\""
		}{"spag", "26ba8184-895f-420d-8591-611784805fe3"},
		Property: map[string]string{
			"scope1": "new-value!!!!!",
			"scope2": "newwwwwwwwww-valueeeee!!!!",
		},
	}
	t := jwt.New()
	t.Set(jwt.IssuerKey, "cap1-agent")
	t.Set(jwt.AudienceKey, "cap1")
	t.Set("events", ev.ToClaim())
	ss, err := jwt.Sign(t, jwa.HS256, []byte("for-agent-sending"))
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, "http://cap1.ztf-proto.k3.ipv6.mobi/ctx/recv", bytes.NewBuffer(ss))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/secevent+jwt")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("respons status code unmatched : %v", resp.Status)
	}
	fmt.Printf("送信に成功  set: %s\n", ss)
	return nil
}
