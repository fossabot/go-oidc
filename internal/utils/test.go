package utils

import (
	"log/slog"
	"net/http"
	"net/http/httptest"

	"github.com/luikymagno/goidc/internal/crud/inmemory"
	"github.com/luikymagno/goidc/internal/unit"
	"github.com/luikymagno/goidc/pkg/goidc"
)

const (
	TestHost  string = "https://example.com"
	TestKeyId string = "rsa256_key"
)

func GetTestInMemoryContext() Context {
	privateJwk := unit.GetTestPrivateRs256Jwk(TestKeyId)
	return Context{
		Configuration: Configuration{
			Profile:                       goidc.OpenIdProfile,
			Host:                          TestHost,
			ClientManager:                 inmemory.NewInMemoryClientManager(),
			GrantSessionManager:           inmemory.NewInMemoryGrantSessionManager(),
			AuthnSessionManager:           inmemory.NewInMemoryAuthnSessionManager(),
			PrivateJwks:                   goidc.JsonWebKeySet{Keys: []goidc.JsonWebKey{privateJwk}},
			DefaultTokenSignatureKeyId:    privateJwk.GetKeyId(),
			DefaultUserInfoSignatureKeyId: privateJwk.GetKeyId(),
			UserInfoSignatureKeyIds:       []string{privateJwk.GetKeyId()},
			GetTokenOptions: func(client goidc.Client, scopes string) (goidc.TokenOptions, error) {
				return goidc.TokenOptions{
					TokenExpiresInSecs: 60,
					TokenFormat:        goidc.JwtTokenFormat,
				}, nil
			},
			AuthenticationSessionTimeoutSecs: 60,
		},
		Request:  httptest.NewRequest(http.MethodGet, TestHost, nil),
		Response: httptest.NewRecorder(),
		Logger:   slog.Default(),
	}
}

func GetDummyTestContext() Context {
	return Context{
		Configuration: Configuration{
			Profile: goidc.OpenIdProfile,
			Host:    TestHost,
		},
		Request: &http.Request{},
		Logger:  slog.Default(),
	}
}

func GetAuthnSessionsFromTestContext(ctx Context) []goidc.AuthnSession {
	sessionManager, _ := ctx.AuthnSessionManager.(*inmemory.InMemoryAuthnSessionManager)
	sessions := make([]goidc.AuthnSession, 0, len(sessionManager.Sessions))
	for _, s := range sessionManager.Sessions {
		sessions = append(sessions, s)
	}

	return sessions
}

func GetGrantSessionsFromTestContext(ctx Context) []goidc.GrantSession {
	manager, _ := ctx.GrantSessionManager.(*inmemory.InMemoryGrantSessionManager)
	tokens := make([]goidc.GrantSession, 0, len(manager.Sessions))
	for _, t := range manager.Sessions {
		tokens = append(tokens, t)
	}

	return tokens
}

// TODO: get unsafe claims from token.
