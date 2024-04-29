package models

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type IdTokenContext struct {
	Nonce                   string
	AdditionalIdTokenClaims map[string]string
	// These values here below are intended to be hashed and placed in the ID token.
	// Then, the ID token can be used as a detached signature for the implict grant.
	AccessToken       string
	AuthorizationCode string
	State             string
}

type TokenContext struct {
	Scopes                []string
	GrantType             constants.GrantType
	AdditionalTokenClaims map[string]string
}

type GrantContext struct {
	Subject  string
	ClientId string
	TokenContext
	IdTokenContext
}

func NewClientCredentialsGrantContext(client Client, req TokenRequest) GrantContext {
	return GrantContext{
		Subject:  client.Id,
		ClientId: client.Id,
		TokenContext: TokenContext{
			Scopes:                unit.SplitStringWithSpaces(req.Scope),
			GrantType:             constants.ClientCredentialsGrant,
			AdditionalTokenClaims: make(map[string]string),
		},
		IdTokenContext: IdTokenContext{
			AdditionalIdTokenClaims: make(map[string]string),
		},
	}
}

func NewAuthorizationCodeGrantContext(session AuthnSession) GrantContext {
	return GrantContext{
		Subject:  session.Subject,
		ClientId: session.ClientId,
		TokenContext: TokenContext{
			Scopes:                session.Scopes,
			GrantType:             constants.AuthorizationCodeGrant,
			AdditionalTokenClaims: session.AdditionalTokenClaims,
		},
		IdTokenContext: IdTokenContext{
			Nonce:                   session.Nonce,
			AdditionalIdTokenClaims: session.AdditionalIdTokenClaims,
		},
	}
}

func NewImplictGrantContext(session AuthnSession) GrantContext {
	return GrantContext{
		Subject:  session.Subject,
		ClientId: session.ClientId,
		TokenContext: TokenContext{
			Scopes:                session.Scopes,
			GrantType:             constants.ImplictGrant,
			AdditionalTokenClaims: session.AdditionalTokenClaims,
		},
		IdTokenContext: IdTokenContext{
			Nonce:                   session.Nonce,
			AdditionalIdTokenClaims: session.AdditionalIdTokenClaims,
		},
	}
}

func NewImplictGrantContextForIdToken(session AuthnSession, idToken IdTokenContext) GrantContext {
	return GrantContext{
		Subject:  session.Subject,
		ClientId: session.ClientId,
		TokenContext: TokenContext{
			Scopes:                session.Scopes,
			GrantType:             constants.ImplictGrant,
			AdditionalTokenClaims: session.AdditionalTokenClaims,
		},
		IdTokenContext: idToken,
	}
}

func NewRefreshTokenGrantContext(session GrantSession) GrantContext {
	return GrantContext{
		Subject:  session.Subject,
		ClientId: session.ClientId,
		TokenContext: TokenContext{
			Scopes:                session.Scopes,
			GrantType:             constants.RefreshTokenGrant,
			AdditionalTokenClaims: session.AdditionalTokenClaims,
		},
		IdTokenContext: IdTokenContext{
			Nonce:                   session.Nonce,
			AdditionalIdTokenClaims: session.AdditionalIdTokenClaims,
		},
	}
}

type ClientAuthnRequest struct {
	ClientIdBasicAuthn     string
	ClientSecretBasicAuthn string
	ClientIdPost           string                        `form:"client_id"`
	ClientSecretPost       string                        `form:"client_secret"`
	ClientAssertionType    constants.ClientAssertionType `form:"client_assertion_type"`
	ClientAssertion        string                        `form:"client_assertion"`
}

type TokenRequest struct {
	ClientAuthnRequest
	GrantType         constants.GrantType `form:"grant_type" binding:"required"`
	Scope             string              `form:"scope"`
	AuthorizationCode string              `form:"code"`
	RedirectUri       string              `form:"redirect_uri"`
	RefreshToken      string              `form:"refresh_token"`
	CodeVerifier      string              `form:"code_verifier"`
}

type TokenResponse struct {
	AccessToken  string              `json:"access_token"`
	IdToken      string              `json:"id_token,omitempty"`
	RefreshToken string              `json:"refresh_token,omitempty"`
	ExpiresIn    int                 `json:"expires_in"`
	TokenType    constants.TokenType `json:"token_type"`
	Scope        string              `json:"scope,omitempty"`
}

type BaseAuthorizeRequest struct {
	RedirectUri         string                        `form:"redirect_uri"`
	Request             string                        `form:"request"`
	Scope               string                        `form:"scope"`
	ResponseType        constants.ResponseType        `form:"response_type"`
	ResponseMode        constants.ResponseMode        `form:"response_mode"`
	State               string                        `form:"state"`
	CodeChallenge       string                        `form:"code_challenge"`
	CodeChallengeMethod constants.CodeChallengeMethod `form:"code_challenge_method"`
	RequestUri          string                        `form:"request_uri"`
	Nonce               string                        `form:"nonce"`
}

type AuthorizeRequest struct {
	ClientId string `form:"client_id"`
	BaseAuthorizeRequest
}

type PARRequest struct {
	ClientAuthnRequest
	BaseAuthorizeRequest
}

func (req PARRequest) ToAuthorizeRequest() AuthorizeRequest {
	return AuthorizeRequest{
		ClientId:             req.ClientIdPost,
		BaseAuthorizeRequest: req.BaseAuthorizeRequest,
	}
}

type PARResponse struct {
	RequestUri string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

type OpenIdConfiguration struct {
	Issuer                   string                            `json:"issuer"`
	AuthorizationEndpoint    string                            `json:"authorization_endpoint"`
	TokenEndpoint            string                            `json:"token_endpoint"`
	UserinfoEndpoint         string                            `json:"userinfo_endpoint"`
	JwksUri                  string                            `json:"jwks_uri"`
	ParEndpoint              string                            `json:"pushed_authorization_request_endpoint"`
	ParIsRequired            bool                              `json:"require_pushed_authorization_requests"`
	ResponseTypes            []constants.ResponseType          `json:"response_types_supported"`
	ResponseModes            []constants.ResponseMode          `json:"response_modes_supported"`
	GrantTypes               []constants.GrantType             `json:"grant_types_supported"`
	SubjectIdentifierTypes   []constants.SubjectIdentifierType `json:"subject_types_supported"`
	IdTokenSigningAlgorithms []jose.SignatureAlgorithm         `json:"id_token_signing_alg_values_supported"`
	ClientAuthnMethods       []constants.ClientAuthnType       `json:"token_endpoint_auth_methods_supported"`
	ScopesSupported          []string                          `json:"scopes_supported"`
	JarmAlgorithms           []string                          `json:"authorization_signing_alg_values_supported"`
}

type RedirectResponse struct {
	ClientId     string
	RedirectUri  string
	ResponseType constants.ResponseType
	ResponseMode constants.ResponseMode
	Parameters   map[string]string
}

func NewRedirectResponseFromSession(session AuthnSession, params map[string]string) RedirectResponse {
	return RedirectResponse{
		ClientId:     session.ClientId,
		RedirectUri:  session.RedirectUri,
		Parameters:   params,
		ResponseType: session.ResponseType,
		ResponseMode: session.ResponseMode,
	}
}

func NewRedirectResponseFromRedirectError(err issues.OAuthRedirectError) RedirectResponse {
	errorParams := map[string]string{
		"error":             string(err.ErrorCode),
		"error_description": err.ErrorDescription,
	}
	if err.State != "" {
		errorParams["state"] = err.State
	}
	return RedirectResponse{
		ClientId:     err.ClientId,
		RedirectUri:  err.RedirectUri,
		Parameters:   errorParams,
		ResponseType: err.ResponseType,
		ResponseMode: err.ResponseMode,
	}
}
