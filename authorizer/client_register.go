package authorizer

import (
	"soturon/client"
	"sync"
)

// ClientRegistration は Oauth2.0 クライアント設定情報を記憶する
type ClientRegistration interface {
	// 新しくクライアント設定情報を登録
	Register(c *client.Config) bool
	// クライアントIDを元に 登録されているか検索
	Find(clientID string) (*client.Config, bool)
}

// NewClientRegistration は新しくRegistrationを作成する
// 引数として、事前に登録したいクライアント情報を与えることができる
func NewClientRegistration(clients map[string]*client.Config) ClientRegistration {
	return &clientRegistration{
		registered: clients,
	}
}

type clientRegistration struct {
	registered map[string]*client.Config
	sync.RWMutex
}

func (cr *clientRegistration) Find(clientID string) (*client.Config, bool) {
	cr.RLock()
	defer cr.RUnlock()
	c, ok := cr.registered[clientID]
	return c, ok
}

func (cr *clientRegistration) Register(c *client.Config) bool {
	cr.Lock()
	defer cr.Unlock()
	_, ok := cr.registered[c.ClientID]
	if ok {
		return false
	}
	cr.registered[c.ClientID] = c
	return true
}
