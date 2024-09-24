package goidc

import (
	"crypto/x509"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
)

const (
	// RefreshTokenLength has an unusual value so to avoid refresh tokens and
	// opaque access token to be confused.
	// This happens since a refresh token is identified by its length during
	// introspection.
	RefreshTokenLength int = 99
)

type Profile string

const (
	ProfileOpenID Profile = "openid"
	ProfileFAPI2  Profile = "fapi2"
)

type GrantType string

const (
	GrantClientCredentials GrantType = "client_credentials"
	GrantAuthorizationCode GrantType = "authorization_code"
	GrantRefreshToken      GrantType = "refresh_token"
	GrantImplicit          GrantType = "implicit"
	// GrantIntrospection is a non standard grant type defined here to indicate
	// when a client is able to introspect tokens.
	GrantIntrospection GrantType = "urn:goidc:oauth2:grant_type:token_intropection"
)

type ResponseType string

const (
	ResponseTypeCode                   ResponseType = "code"
	ResponseTypeIDToken                ResponseType = "id_token"
	ResponseTypeToken                  ResponseType = "token"
	ResponseTypeCodeAndIDToken         ResponseType = "code id_token"
	ResponseTypeCodeAndToken           ResponseType = "code token"
	ResponseTypeIDTokenAndToken        ResponseType = "id_token token"
	ResponseTypeCodeAndIDTokenAndToken ResponseType = "code id_token token"
)

func (rt ResponseType) Contains(responseType ResponseType) bool {
	return slices.Contains(strings.Split(string(rt), " "), string(responseType))
}

func (rt ResponseType) IsImplicit() bool {
	return rt.Contains(ResponseTypeIDToken) || rt.Contains(ResponseTypeToken)
}

type ResponseMode string

const (
	ResponseModeQuery       ResponseMode = "query"
	ResponseModeFragment    ResponseMode = "fragment"
	ResponseModeFormPost    ResponseMode = "form_post"
	ResponseModeQueryJWT    ResponseMode = "query.jwt"
	ResponseModeFragmentJWT ResponseMode = "fragment.jwt"
	ResponseModeFormPostJWT ResponseMode = "form_post.jwt"
	ResponseModeJWT         ResponseMode = "jwt"
)

func (rm ResponseMode) IsJARM() bool {
	return rm == ResponseModeQueryJWT || rm == ResponseModeFragmentJWT ||
		rm == ResponseModeFormPostJWT || rm == ResponseModeJWT
}

func (rm ResponseMode) IsPlain() bool {
	return rm == ResponseModeQuery || rm == ResponseModeFragment ||
		rm == ResponseModeFormPost
}

func (rm ResponseMode) IsQuery() bool {
	return rm == ResponseModeQuery || rm == ResponseModeQueryJWT
}

type ClientAuthnType string

const (
	ClientAuthnNone          ClientAuthnType = "none"
	ClientAuthnSecretBasic   ClientAuthnType = "client_secret_basic"
	ClientAuthnSecretPost    ClientAuthnType = "client_secret_post"
	ClientAuthnSecretJWT     ClientAuthnType = "client_secret_jwt"
	ClientAuthnPrivateKeyJWT ClientAuthnType = "private_key_jwt"
	ClientAuthnTLS           ClientAuthnType = "tls_client_auth"
	ClientAuthnSelfSignedTLS ClientAuthnType = "self_signed_tls_client_auth"
)

type ClientAssertionType string

const (
	AssertionTypeJWTBearer ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

type TokenType string

const (
	TokenTypeBearer TokenType = "Bearer"
	TokenTypeDPoP   TokenType = "DPoP"
)

const (
	ClaimTokenID                        string = "jti"
	ClaimIssuer                         string = "iss"
	ClaimSubject                        string = "sub"
	ClaimAudience                       string = "aud"
	ClaimClientID                       string = "client_id"
	ClaimExpiry                         string = "exp"
	ClaimIssuedAt                       string = "iat"
	ClaimScope                          string = "scope"
	ClaimNonce                          string = "nonce"
	ClaimAuthenticationTime             string = "auth_time"
	ClaimAuthenticationMethodReferences string = "amr"
	ClaimAuthenticationContextReference string = "acr"
	ClaimProfile                        string = "profile"
	ClaimEmail                          string = "email"
	ClaimEmailVerified                  string = "email_verified"
	ClaimAddress                        string = "address"
	ClaimAuthorizationDetails           string = "authorization_details"
	ClaimAccessTokenHash                string = "at_hash"
	ClaimAuthorizationCodeHash          string = "c_hash"
	ClaimStateHash                      string = "s_hash"
)

type KeyUsage string

const (
	KeyUsageSignature  KeyUsage = "sig"
	KeyUsageEncryption KeyUsage = "enc"
)

type CodeChallengeMethod string

const (
	CodeChallengeMethodSHA256 CodeChallengeMethod = "S256"
	CodeChallengeMethodPlain  CodeChallengeMethod = "plain"
)

// SubjectIdentifierType defines how the auth server provides subject
// identifiers to its clients.
// For more information,
// see: https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes
type SubjectIdentifierType string

const (
	// SubjectIdentifierPublic makes the server provide the same subject
	// identifier to all clients.
	SubjectIdentifierPublic SubjectIdentifierType = "public"
	// TODO: Implement pairwise.
)

const (
	HeaderDPoP string = "DPoP"
	// HeaderClientCert is the header used to transmit a client
	// certificate that was validated by a trusted source.
	// The value in this header is expected to be the URL encoding of the
	// client's certificate in PEM format.
	HeaderClientCert string = "X-Client-Cert"
)

type AuthnStatus string

const (
	StatusSuccess    AuthnStatus = "success"
	StatusInProgress AuthnStatus = "in_progress"
	StatusFailure    AuthnStatus = "failure"
)

type TokenFormat string

const (
	TokenFormatJWT    TokenFormat = "jwt"
	TokenFormatOpaque TokenFormat = "opaque"
)

// AMR defines a type for authentication method references.
type AMR string

const (
	AMRFacialRecognition            AMR = "face"
	AMRFingerPrint                  AMR = "fpt"
	AMRGeolocation                  AMR = "geo"
	AMRHardwareSecuredKey           AMR = "hwk"
	AMRIrisScan                     AMR = "iris"
	AMRMultipleFactor               AMR = "mfa"
	AMROneTimePassoword             AMR = "otp"
	AMRPassword                     AMR = "pwd"
	AMRPersonalIDentificationNumber AMR = "pin"
	AMRRiskBased                    AMR = "rba"
	AMRSMS                          AMR = "sms"
	AMRSoftwareSecuredKey           AMR = "swk"
)

type DisplayValue string

const (
	DisplayValuePage  DisplayValue = "page"
	DisplayValuePopUp DisplayValue = "popup"
	DisplayValueTouch DisplayValue = "touch"
	DisplayValueWAP   DisplayValue = "wap"
)

type PromptType string

const (
	PromptTypeNone          PromptType = "none"
	PromptTypeLogin         PromptType = "login"
	PromptTypeConsent       PromptType = "consent"
	PromptTypeSelectAccount PromptType = "select_account"
)

type ClaimType string

const (
	ClaimTypeNormal      ClaimType = "normal"
	ClaimTypeAggregated  ClaimType = "aggregated"
	ClaimTypeDistributed ClaimType = "distributed"
)

type TokenTypeHint string

const (
	TokenHintAccess  TokenTypeHint = "access_token"
	TokenHintRefresh TokenTypeHint = "refresh_token"
)

// ACR defines a type for authentication context references.
type ACR string

const (
	ACRNoAssuranceLevel      ACR = "0"
	ACRMaceIncommonIAPSilver ACR = "urn:mace:incommon:iap:silver"
	ACRMaceIncommonIAPBronze ACR = "urn:mace:incommon:iap:bronze"
)

type ClientCertFunc func(*http.Request) (*x509.Certificate, error)

type MiddlewareFunc func(next http.Handler) http.Handler

// HandleDynamicClientFunc defines a function that will be executed during DCR
// and DCM.
// It can be used to modify the client and perform custom validations.
type HandleDynamicClientFunc func(*http.Request, *ClientMetaInfo) error

// RenderErrorFunc defines a function that will be called when errors
// during the authorization request cannot be handled.
type RenderErrorFunc func(http.ResponseWriter, *http.Request, error) error

type HandleErrorFunc func(*http.Request, error)

var (
	ScopeOpenID        = NewScope("openid")
	ScopeProfile       = NewScope("profile")
	ScopeEmail         = NewScope("email")
	ScopeAddress       = NewScope("address")
	ScopeOfflineAccess = NewScope("offline_access")
)

// MatchScopeFunc defines a function executed to verify whether a requested
// scope is a match or not.
type MatchScopeFunc func(requestedScope string) bool

type Scope struct {
	// ID is the string representation of the scope.
	// Its value will be published as is in the well known endpoint.
	ID string
	// Matches validates if a requested scope matches the current scope.
	Matches MatchScopeFunc
}

// NewScope creates a scope where the validation logic is simple string comparison.
func NewScope(scope string) Scope {
	return Scope{
		ID: scope,
		Matches: func(requestedScope string) bool {
			return scope == requestedScope
		},
	}
}

// NewDynamicScope creates a scope with custom logic that will be used to validate
// the scopes requested by the client.
//
//	dynamicScope := NewDynamicScope(
//		"payment",
//		func(requestedScope string) bool {
//			return strings.HasPrefix(requestedScope, "payment:")
//		},
//	)
//
//	// This results in true.
//	dynamicScope.Matches("payment:30")
func NewDynamicScope(
	scope string,
	matchingFunc MatchScopeFunc,
) Scope {
	return Scope{
		ID:      scope,
		Matches: matchingFunc,
	}
}

type HTTPClientFunc func(*http.Request) *http.Client

type ShouldIssueRefreshTokenFunc func(*Client, GrantInfo) bool

// TokenOptionsFunc defines a function that returns token configuration and is
// executed when issuing access tokens.
type TokenOptionsFunc func(*Client, GrantInfo) TokenOptions

// TokenOptions defines a template for generating access tokens.
type TokenOptions struct {
	Format            TokenFormat
	LifetimeSecs      int
	JWTSignatureKeyID string
	OpaqueLength      int
}

func NewJWTTokenOptions(
	sigKeyID string,
	lifetimeSecs int,
) TokenOptions {
	return TokenOptions{
		Format:            TokenFormatJWT,
		LifetimeSecs:      lifetimeSecs,
		JWTSignatureKeyID: sigKeyID,
	}
}

func NewOpaqueTokenOptions(
	tokenLength int,
	lifetimeSecs int,
) TokenOptions {
	return TokenOptions{
		Format:       TokenFormatOpaque,
		LifetimeSecs: lifetimeSecs,
		OpaqueLength: tokenLength,
	}
}

// AuthnFunc executes the user authentication logic.
// If it returns [StatusSuccess], the flow will end successfully and the client
// will be granted the accesses the user consented.
// If it returns [StatusFailure], the flow will end with failure and the client
// will be denied access.
// If it return [StatusInProgress], the flow will be suspended so an interaction
// with the user via the user agent can happen. The flow can be resumed at the
// callback endpoint with the session callback ID.
type AuthnFunc func(http.ResponseWriter, *http.Request, *AuthnSession) AuthnStatus

// SetUpAuthnFunc is responsible for initiating the authentication session.
// It returns true when the policy is ready to executed and false for when the
// policy should be skipped.
type SetUpAuthnFunc func(*http.Request, *Client, *AuthnSession) bool

// AuthnPolicy holds information on how to set up an authentication session and
// authenticate users.
type AuthnPolicy struct {
	ID           string
	SetUp        SetUpAuthnFunc
	Authenticate AuthnFunc
}

// NewPolicy creates a policy that will be selected based on setUpFunc and that
// authenticates users with authnFunc.
func NewPolicy(
	id string,
	setUpFunc SetUpAuthnFunc,
	authnFunc AuthnFunc,
) AuthnPolicy {
	return AuthnPolicy{
		ID:           id,
		Authenticate: authnFunc,
		SetUp:        setUpFunc,
	}
}

type TokenConfirmation struct {
	JWKThumbprint               string `json:"jkt"`
	ClientCertificateThumbprint string `json:"x5t#S256"`
}

type TokenInfo struct {
	IsActive              bool                  `json:"active"`
	Reason                string                `json:"-"` // TODO. Fill this.
	Type                  TokenTypeHint         `json:"hint,omitempty"`
	Scopes                string                `json:"scope,omitempty"`
	AuthorizationDetails  []AuthorizationDetail `json:"authorization_details,omitempty"`
	ClientID              string                `json:"client_id,omitempty"`
	Subject               string                `json:"sub,omitempty"`
	ExpiresAtTimestamp    int                   `json:"exp,omitempty"`
	Confirmation          *TokenConfirmation    `json:"cnf,omitempty"`
	Resources             Resources             `json:"aud,omitempty"`
	AdditionalTokenClaims map[string]any        `json:"-"`
}

func (ti TokenInfo) MarshalJSON() ([]byte, error) {

	type tokenInfo TokenInfo
	attributesBytes, err := json.Marshal(tokenInfo(ti))
	if err != nil {
		return nil, err
	}

	var rawValues map[string]any
	if err := json.Unmarshal(attributesBytes, &rawValues); err != nil {
		return nil, err
	}

	// Inline the additional claims.
	for k, v := range ti.AdditionalTokenClaims {
		rawValues[k] = v
	}

	return json.Marshal(rawValues)
}

type AuthorizationParameters struct {
	RequestURI           string                `json:"request_uri,omitempty"`
	RequestObject        string                `json:"request,omitempty"`
	RedirectURI          string                `json:"redirect_uri,omitempty"`
	ResponseMode         ResponseMode          `json:"response_mode,omitempty"`
	ResponseType         ResponseType          `json:"response_type,omitempty"`
	Scopes               string                `json:"scope,omitempty"`
	State                string                `json:"state,omitempty"`
	Nonce                string                `json:"nonce,omitempty"`
	CodeChallenge        string                `json:"code_challenge,omitempty"`
	CodeChallengeMethod  CodeChallengeMethod   `json:"code_challenge_method,omitempty"`
	Prompt               PromptType            `json:"prompt,omitempty"`
	MaxAuthnAgeSecs      *int                  `json:"max_age,omitempty"`
	Display              DisplayValue          `json:"display,omitempty"`
	ACRValues            string                `json:"acr_values,omitempty"`
	Claims               *ClaimsObject         `json:"claims,omitempty"`
	AuthorizationDetails []AuthorizationDetail `json:"authorization_details,omitempty"`
	Resources            Resources             `json:"resource,omitempty"`
	DPoPJWKThumbprint    string                `json:"dpop_jkt,omitempty"`
	LoginHint            string                `json:"login_hint,omitempty"`
	IDTokenHint          string                `json:"id_token_hint,omitempty"`
}

type Resources []string

func (r *Resources) UnmarshalJSON(data []byte) error {
	var resource string
	if err := json.Unmarshal(data, &resource); err == nil {
		*r = []string{resource}
		return nil
	}

	var resources []string
	if err := json.Unmarshal(data, &resources); err != nil {
		return err
	}

	*r = resources
	return nil
}

func (resources Resources) MarshalJSON() ([]byte, error) {
	if len(resources) == 1 {
		return json.Marshal(resources[0])
	}

	return json.Marshal([]string(resources))
}

type ClaimsObject struct {
	UserInfo map[string]ClaimObjectInfo `json:"userinfo"`
	IDToken  map[string]ClaimObjectInfo `json:"id_token"`
}

// UserInfoEssentials returns all the essentials claims requested by the client
// to be returned in the userinfo endpoint.
func (claims ClaimsObject) UserInfoEssentials() []string {
	return essentials(claims.UserInfo)
}

// IDTokenEssentials returns all the essentials claims requested by the client
// to be returned in the ID token.
func (claims ClaimsObject) IDTokenEssentials() []string {
	return essentials(claims.IDToken)
}

// UserInfoClaim returns the claim object info if present.
func (claims ClaimsObject) UserInfoClaim(claimName string) (ClaimObjectInfo, bool) {
	return claim(claimName, claims.UserInfo)
}

// IDTokenClaim returns the claim object info if present.
func (claims ClaimsObject) IDTokenClaim(claimName string) (ClaimObjectInfo, bool) {
	return claim(claimName, claims.IDToken)
}

func claim(claim string, claims map[string]ClaimObjectInfo) (ClaimObjectInfo, bool) {
	for name, claimInfo := range claims {
		if name == claim {
			return claimInfo, true
		}
	}
	return ClaimObjectInfo{}, false
}

func essentials(claims map[string]ClaimObjectInfo) []string {
	var essentialClaims []string
	for name, claim := range claims {
		if claim.IsEssential {
			essentialClaims = append(essentialClaims, name)
		}
	}
	return essentialClaims
}

type ClaimObjectInfo struct {
	IsEssential bool     `json:"essential"`
	Value       string   `json:"value"`
	Values      []string `json:"values"`
}

// AuthorizationDetail represents an authorization details as a map.
// It is a map instead of a struct, because its fields vary a lot depending on
// the use case.
type AuthorizationDetail map[string]any

func (d AuthorizationDetail) Type() string {
	return d.string("type")
}

func (d AuthorizationDetail) Identifier() string {
	return d.string("identifier")
}

func (d AuthorizationDetail) Locations() []string {
	return d.stringSlice("locations")
}

func (d AuthorizationDetail) Actions() []string {
	return d.stringSlice("actions")
}

func (d AuthorizationDetail) DataTypes() []string {
	return d.stringSlice("datatypes")
}

func (d AuthorizationDetail) stringSlice(key string) []string {
	value, ok := d[key]
	if !ok {
		return nil
	}

	slice, ok := value.([]string)
	if !ok {
		return nil
	}

	return slice
}

func (d AuthorizationDetail) string(key string) string {
	value, ok := d[key]
	if !ok {
		return ""
	}

	s, ok := value.(string)
	if !ok {
		return ""
	}

	return s
}
