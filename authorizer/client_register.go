package authorizer

import (
	"soturon/client"
	"sync"
)

type ClientRegistration interface {
	Register(c *client.Config) bool
	Find(clientID string) (*client.Config, bool)
}

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
