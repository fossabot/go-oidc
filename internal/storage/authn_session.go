package storage

import (
	"context"
	"errors"
	"sync"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type AuthnSessionManager struct {
	Sessions map[string]*goidc.AuthnSession
	mu       sync.RWMutex
}

func NewAuthnSessionManager() *AuthnSessionManager {
	return &AuthnSessionManager{
		Sessions: make(map[string]*goidc.AuthnSession),
	}
}

func (m *AuthnSessionManager) Save(
	_ context.Context,
	session *goidc.AuthnSession,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.Sessions[session.ID] = session
	return nil
}

func (m *AuthnSessionManager) SessionByCallbackID(
	_ context.Context,
	callbackID string,
) (
	*goidc.AuthnSession,
	error,
) {
	session, exists := m.firstSession(func(s *goidc.AuthnSession) bool {
		return s.CallbackID == callbackID
	})
	if !exists {
		return nil, errors.New("entity not found")
	}

	return session, nil
}

func (m *AuthnSessionManager) SessionByAuthorizationCode(
	_ context.Context,
	authorizationCode string,
) (
	*goidc.AuthnSession,
	error,
) {
	session, exists := m.firstSession(func(s *goidc.AuthnSession) bool {
		return s.AuthorizationCode == authorizationCode
	})
	if !exists {
		return nil, errors.New("entity not found")
	}

	return session, nil
}

func (m *AuthnSessionManager) SessionByReferenceID(
	_ context.Context,
	requestURI string,
) (
	*goidc.AuthnSession,
	error,
) {
	session, exists := m.firstSession(func(s *goidc.AuthnSession) bool {
		return s.ReferenceID == requestURI
	})
	if !exists {
		return nil, errors.New("entity not found")
	}

	return session, nil
}

func (m *AuthnSessionManager) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.Sessions, id)
	return nil
}

func (m *AuthnSessionManager) firstSession(
	condition func(*goidc.AuthnSession) bool,
) (
	*goidc.AuthnSession,
	bool,
) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Convert the map to a slice of sessions.
	sessions := make([]*goidc.AuthnSession, 0, len(m.Sessions))
	for _, s := range m.Sessions {
		sessions = append(sessions, s)
	}

	return findFirst(sessions, condition)
}
