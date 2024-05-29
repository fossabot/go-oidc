package models

import (
	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type AuthnSession struct {
	Id                 string
	Profile            constants.Profile
	CallbackId         string
	GrantModelId       string
	PolicyId           string
	AuthnSequenceIndex int
	CreatedAtTimestamp int
	Subject            string
	ClientId           string
	AuthorizationParameters
	GrantedScopes             string
	AuthorizationCode         string
	AuthorizedAtTimestamp     int
	PushedParameters          map[string]string // Parameters sent using the PAR endpoint.
	Store                     map[string]string // Allow the developer to store information in memory and, hence, between steps.
	AdditionalTokenClaims     map[string]string // Allow the developer to map new (or override the default) claims to the access token.
	IdTokenSignatureAlgorithm jose.SignatureAlgorithm
	AdditionalIdTokenClaims   map[string]string // Allow the developer to map new (or override the default) claims to the ID token.
}

func NewSession(authParams AuthorizationParameters, client Client) AuthnSession {

	return AuthnSession{
		Id:                        uuid.NewString(),
		ClientId:                  client.Id,
		AuthorizationParameters:   authParams,
		CreatedAtTimestamp:        unit.GetTimestampNow(),
		PushedParameters:          make(map[string]string),
		Store:                     make(map[string]string),
		AdditionalTokenClaims:     make(map[string]string),
		IdTokenSignatureAlgorithm: client.IdTokenSignatureAlgorithm,
		AdditionalIdTokenClaims:   make(map[string]string),
	}
}

func (session *AuthnSession) Push(reqCtx *gin.Context) {
	session.RequestUri = unit.GenerateRequestUri()
	session.PushedParameters = extractPushedParams(reqCtx)
}

func (session *AuthnSession) Start(policyId string) {
	session.PolicyId = policyId
	session.AuthnSequenceIndex = 0
	session.CallbackId = unit.GenerateCallbackId()
	// FIXME: To think about:Treating the request_uri as one-time use will cause problems when the user refreshes the page.
	session.RequestUri = ""
}

// Update the session with the parameters from an authorization request
// The parameters already present in the session take priority.
func (session *AuthnSession) UpdateParams(params AuthorizationParameters) {
	session.AuthorizationParameters = session.AuthorizationParameters.Merge(params)
}

func extractPushedParams(reqCtx *gin.Context) map[string]string {
	// Load the parameters sent using PAR.
	if err := reqCtx.Request.ParseForm(); err != nil {
		return map[string]string{}
	}

	pushedParams := make(map[string]string)
	for param, values := range reqCtx.Request.PostForm {
		pushedParams[param] = values[0]
	}

	return pushedParams
}

func (session *AuthnSession) SetUserId(userId string) {
	session.Subject = userId
}

// Sava a paramater in the session so it can be used across steps.
func (session *AuthnSession) SaveParameter(key string, value string) {
	session.Store[key] = value
}

func (session *AuthnSession) GetParameter(key string) string {
	return session.Store[key]
}

// Set a new claim that will be mapped in the access token when issued.
func (session *AuthnSession) SetCustomTokenClaim(key string, value string) {
	session.AdditionalTokenClaims[key] = value
}

func (session *AuthnSession) GetCustomTokenClaim(key string, value string) string {
	return session.AdditionalTokenClaims[key]
}

// Set a new claim that will be mapped in the ID token when issued.
func (session *AuthnSession) SetCustomIdTokenClaim(key string, value string) {
	session.AdditionalIdTokenClaims[key] = value
}

func (session *AuthnSession) GetCustomIdTokenClaim(key string, value string) string {
	return session.AdditionalIdTokenClaims[key]
}

func (session *AuthnSession) IsPushedRequestExpired(parLifetimeSecs int) bool {
	return unit.GetTimestampNow() > session.CreatedAtTimestamp+parLifetimeSecs
}

func (session *AuthnSession) IsAuthorizationCodeExpired() bool {
	return unit.GetTimestampNow() > session.AuthorizedAtTimestamp+constants.AuthorizationCodeLifetimeSecs
}

func (session *AuthnSession) InitAuthorizationCode() string {
	session.AuthorizationCode = unit.GenerateAuthorizationCode()
	session.AuthorizedAtTimestamp = unit.GetTimestampNow()
	return session.AuthorizationCode
}

func (session *AuthnSession) GrantScopes(scopes string) {
	session.GrantedScopes = scopes
}
