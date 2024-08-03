package goidc

import (
	"crypto/tls"
	"net/http"
	"slices"
	"strings"
)

const (
	DefaultAuthenticationSessionTimeoutSecs     = 30 * 60
	DefaultIDTokenLifetimeSecs                  = 600
	CallbackIDLength                        int = 20
	RequestURILength                        int = 20
	AuthorizationCodeLifetimeSecs           int = 60
	AuthorizationCodeLength                 int = 30
	// RefreshTokenLength has an unusual value so to avoid refresh tokens and opaque access token to be confused.
	// This happens since a refresh token is identified by its length during introspection.
	RefreshTokenLength              int = 99
	DefaultRefreshTokenLifetimeSecs int = 6000
	DynamicClientIDLength           int = 30
	// ClientSecretLength must be at least 64 characters, so that it can be also used for
	// symmetric encryption during, for instance, authentication with client_secret_jwt.
	// For client_secret_jwt, the highest algorithm we accept is HS512 which requires a key of at least 512 bits (64 characters).
	ClientSecretLength            int    = 64
	RegistrationAccessTokenLength int    = 50
	DefaultTokenLifetimeSecs      int    = 300
	ProtectedParamPrefix          string = "p_"
)

var FAPIAllowedCipherSuites []uint16 = []uint16{
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}

type Profile string

const (
	ProfileOpenID Profile = "oidc_profile"
	ProfileFAPI2  Profile = "fapi2_profile"
)

type ContextKey string

const CorrelationIDKey ContextKey = "correlation_id"

type GrantType string

const (
	GrantClientCredentials GrantType = "client_credentials"
	GrantAuthorizationCode GrantType = "authorization_code"
	GrantRefreshToken      GrantType = "refresh_token"
	GrantImplicit          GrantType = "implicit"
	GrantIntrospection     GrantType = "urn:goidc:oauth2:grant_type:token_intropection"
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

// DefaultResponseMode returns the response mode based on the response type.
// According to "5. Definitions of Multiple-Valued Response Type Combinations" of https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations.
func (rt ResponseType) DefaultResponseMode(jarm bool) ResponseMode {
	if rt.IsImplicit() {
		if jarm {
			return ResponseModeFragmentJWT
		}
		return ResponseModeFragment
	}

	if jarm {
		return ResponseModeQueryJWT
	}
	return ResponseModeQuery
}

type ResponseMode string

const (
	ResponseModeQuery    ResponseMode = "query"
	ResponseModeFragment ResponseMode = "fragment"
	ResponseModeFormPost ResponseMode = "form_post"
	// JARM - JWT Secured Authorization Response Mode.
	// For more information, see https://openid.net/specs-v2-jarm.html.
	ResponseModeQueryJWT    ResponseMode = "query.jwt"
	ResponseModeFragmentJWT ResponseMode = "fragment.jwt"
	ResponseModeFormPostJWT ResponseMode = "form_post.jwt"
	ResponseModeJWT         ResponseMode = "jwt"
)

func (rm ResponseMode) IsJARM() bool {
	return rm == ResponseModeQueryJWT || rm == ResponseModeFragmentJWT || rm == ResponseModeFormPostJWT || rm == ResponseModeJWT
}

func (rm ResponseMode) IsPlain() bool {
	return rm == ResponseModeQuery || rm == ResponseModeFragment || rm == ResponseModeFormPost
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

// For more information, see: https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes
type SubjectIdentifierType string

const (
	// The server provides the same sub (subject) value to all Clients.
	SubjectIdentifierPublic SubjectIdentifierType = "public"
	// TODO: Implement pairwise.
)

type ErrorCode string

const (
	ErrorCodeAccessDenied                ErrorCode = "access_denied"
	ErrorCodeInvalidClient               ErrorCode = "invalid_client"
	ErrorCodeInvalidGrant                ErrorCode = "invalid_grant"
	ErrorCodeInvalidRequest              ErrorCode = "invalid_request"
	ErrorCodeUnauthorizedClient          ErrorCode = "unauthorized_client"
	ErrorCodeInvalidScope                ErrorCode = "invalid_scope"
	ErrorCodeInvalidAuthorizationDetails ErrorCode = "invalid_authorization_details"
	ErrorCodeUnsupportedGrantType        ErrorCode = "unsupported_grant_type"
	ErrorCodeInvalidResquestObject       ErrorCode = "invalid_request_object"
	ErrorCodeInvalidToken                ErrorCode = "invalid_token"
	ErrorCodeInternalError               ErrorCode = "internal_error"
)

func (ec ErrorCode) StatusCode() int {
	switch ec {
	case ErrorCodeAccessDenied:
		return http.StatusForbidden
	case ErrorCodeInvalidClient, ErrorCodeInvalidToken, ErrorCodeUnauthorizedClient:
		return http.StatusUnauthorized
	case ErrorCodeInternalError:
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}

const (
	HeaderDPoP string = "DPoP"
	// HeaderClientCertificate is the header used to transmit a client certificate that was validated by a trusted source.
	// The value in this header is expected to be the URL encoding of the client's certificate in PEM format.
	HeaderClientCertificate string = "X-Client-Cert"
)

const ClientSecretCharset string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

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

type EndpointPath string

const (
	EndpointWellKnown                  EndpointPath = "/.well-known/openid-configuration"
	EndpointJSONWebKeySet              EndpointPath = "/jwks"
	EndpointPushedAuthorizationRequest EndpointPath = "/par"
	EndpointAuthorization              EndpointPath = "/authorize"
	EndpointToken                      EndpointPath = "/token"
	EndpointUserInfo                   EndpointPath = "/userinfo"
	EndpointDynamicClient              EndpointPath = "/register"
	EndpointTokenIntrospection         EndpointPath = "/introspect"
)

type AuthenticationMethodReference string

const (
	AuthenticationMethodFacialRecognition            AuthenticationMethodReference = "face"
	AuthenticationMethodFingerPrint                  AuthenticationMethodReference = "fpt"
	AuthenticationMethodGeolocation                  AuthenticationMethodReference = "geo"
	AuthenticationMethodHardwareSecuredKey           AuthenticationMethodReference = "hwk"
	AuthenticationMethodIrisScan                     AuthenticationMethodReference = "iris"
	AuthenticationMethodMultipleFactor               AuthenticationMethodReference = "mfa"
	AuthenticationMethodOneTimePassoword             AuthenticationMethodReference = "otp"
	AuthenticationMethodPassword                     AuthenticationMethodReference = "pwd"
	AuthenticationMethodPersonalIDentificationNumber AuthenticationMethodReference = "pin"
	AuthenticationMethodRiskBased                    AuthenticationMethodReference = "rba"
	AuthenticationMethodSMS                          AuthenticationMethodReference = "sms"
	AuthenticationMethodSoftwareSecuredKey           AuthenticationMethodReference = "swk"
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

type AuthenticationContextReference string

const (
	ACRNoAssuranceLevel      AuthenticationContextReference = "0"
	ACRMaceIncommonIAPSilver AuthenticationContextReference = "urn:mace:incommon:iap:silver"
	ACRMaceIncommonIAPBronze AuthenticationContextReference = "urn:mace:incommon:iap:bronze"
)