package session

import (
	"soturon/util"
	"sync"
)

type Session interface {
	Find(key string) (v interface{}, ok bool)
	Set(key string, v interface{})
}

func NewSession() Session {
	return &session{
		s: make(map[string]interface{}),
	}
}

type session struct {
	s map[string]interface{}
	sync.RWMutex
}

func (s *session) Find(key string) (v interface{}, ok bool) {
	s.RLock()
	defer s.RUnlock()
	v, ok = s.s[key]
	return
}

func (s *session) Set(key string, v interface{}) {
	s.Lock()
	defer s.Unlock()
	s.s[key] = v
}

type Manager interface {
	UniqueID() string
	Delete(string)
	Find(string) (Session, bool)
	Set(sID, k string, v interface{}) bool
}

func NewManager() Manager {
	return &manager{
		s: make(map[string]Session),
	}
}

type manager struct {
	s map[string]Session
	sync.RWMutex
}

func (m *manager) UniqueID() string {
	m.Lock()
	defer m.Unlock()
	var sessionID string
	for ok := true; ok; {
		sessionID = util.RandString(30)
		_, ok = m.s[sessionID]
	}
	m.s[sessionID] = NewSession()
	return sessionID
}

func (m *manager) Delete(sID string) {
	m.Lock()
	defer m.Unlock()
	delete(m.s, sID)
}

func (m *manager) Find(sID string) (Session, bool) {
	m.RLock()
	defer m.RUnlock()
	s, ok := m.s[sID]
	return s, ok
}

func (m *manager) Set(sID, k string, v interface{}) bool {
	m.RLock()
	defer m.RUnlock()
	s, ok := m.s[sID]
	if !ok {
		return false
	}
	s.Set(k, v)
	return true
}
