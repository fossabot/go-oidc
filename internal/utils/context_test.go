package utils_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetClientSignatureAlgorithms(t *testing.T) {
	// Given.
	ctx := utils.OAuthContext{}
	// Then.
	assert.Nil(t, ctx.ClientSignatureAlgorithms())

	// Given.
	ctx.PrivateKeyJWTSignatureAlgorithms = []jose.SignatureAlgorithm{jose.PS256}
	// Then.
	assert.Equal(t, []jose.SignatureAlgorithm{jose.PS256}, ctx.ClientSignatureAlgorithms())

	// Given.
	ctx.ClientSecretJWTSignatureAlgorithms = []jose.SignatureAlgorithm{jose.HS256}
	// Then.
	assert.Equal(t, []jose.SignatureAlgorithm{jose.PS256, jose.HS256}, ctx.ClientSignatureAlgorithms())
}

func TestGetIntrospectionClientSignatureAlgorithms(t *testing.T) {
	// Given.
	ctx := utils.OAuthContext{}
	// Then.
	assert.Nil(t, ctx.IntrospectionClientSignatureAlgorithms())

	// Given.
	ctx.IntrospectionClientAuthnMethods = append(ctx.IntrospectionClientAuthnMethods, goidc.ClientAuthnPrivateKeyJWT)
	ctx.PrivateKeyJWTSignatureAlgorithms = []jose.SignatureAlgorithm{jose.PS256}
	// Then.
	assert.Equal(t, []jose.SignatureAlgorithm{jose.PS256}, ctx.IntrospectionClientSignatureAlgorithms())

	// Given.
	ctx.IntrospectionClientAuthnMethods = append(ctx.IntrospectionClientAuthnMethods, goidc.ClientAuthnSecretJWT)
	ctx.ClientSecretJWTSignatureAlgorithms = []jose.SignatureAlgorithm{jose.HS256}
	// Then.
	assert.Equal(t, []jose.SignatureAlgorithm{jose.PS256, jose.HS256}, ctx.IntrospectionClientSignatureAlgorithms())
}

func TestGetDPOPJWT_HappyPath(t *testing.T) {
	// Given the DPOP header was informed.
	ctx := utils.OAuthContext{
		Request: httptest.NewRequest(http.MethodGet, utils.TestHost, nil),
	}
	ctx.Request.Header.Set(goidc.HeaderDPOP, "dpop_jwt")

	// When.
	dpopJwt, ok := ctx.DPOPJWT()

	// Then.
	require.True(t, ok)
	assert.Equal(t, "dpop_jwt", dpopJwt)
}

func TestGetDPOPJWT_DPOPHeaderNotInCanonicalFormat(t *testing.T) {
	// Given.
	ctx := utils.OAuthContext{
		Request: httptest.NewRequest(http.MethodGet, utils.TestHost, nil),
	}
	ctx.Request.Header.Set(strings.ToLower(goidc.HeaderDPOP), "dpop_jwt")

	// When.
	dpopJwt, ok := ctx.DPOPJWT()

	// Then.
	require.True(t, ok)
	assert.Equal(t, "dpop_jwt", dpopJwt)
}

func TestGetDPOPJWT_DPOPHeaderNotInformed(t *testing.T) {
	// Given.
	ctx := utils.OAuthContext{
		Request: httptest.NewRequest(http.MethodGet, utils.TestHost, nil),
	}
	// When.
	_, ok := ctx.DPOPJWT()

	// Then.
	require.False(t, ok)
}

func TestGetDPOPJWT_MultipleValuesInTheDPOPHeader(t *testing.T) {
	// Given.
	ctx := utils.OAuthContext{
		Request: httptest.NewRequest(http.MethodGet, utils.TestHost, nil),
	}
	ctx.Request.Header.Add(goidc.HeaderDPOP, "dpop_jwt1")
	ctx.Request.Header.Add(goidc.HeaderDPOP, "dpop_jwt2")

	// When.
	_, ok := ctx.DPOPJWT()

	// Then.
	require.False(t, ok)
}

func TestExecuteDCRPlugin_HappyPath(t *testing.T) {
	// Given.
	ctx := utils.OAuthContext{}
	clientInfo := goidc.ClientMetaInfo{}

	// Then.
	assert.NotPanics(t, func() { ctx.ExecuteDCRPlugin(&clientInfo) })

	// Given.
	ctx.DCRPlugin = func(ctx goidc.OAuthContext, clientInfo *goidc.ClientMetaInfo) {
		clientInfo.AuthnMethod = goidc.ClientAuthnNone
	}

	// When.
	ctx.ExecuteDCRPlugin(&clientInfo)

	// Then.
	assert.Equal(t, goidc.ClientAuthnNone, clientInfo.AuthnMethod)
}

func TestGetAudiences_HappyPath(t *testing.T) {
	// Given.
	ctx := utils.OAuthContext{}
	ctx.Host = utils.TestHost

	// When.
	audiences := ctx.Audiences()

	// Then.
	assert.Contains(t, audiences, ctx.Host)
	assert.Contains(t, audiences, ctx.Host+string(goidc.EndpointToken))
	assert.Contains(t, audiences, ctx.Host+string(goidc.EndpointPushedAuthorizationRequest))
	assert.Contains(t, audiences, ctx.Host+string(goidc.EndpointUserInfo))
}

func TestGetAudiences_MTLSIsEnabled(t *testing.T) {
	// Given.
	ctx := utils.OAuthContext{}
	ctx.Host = utils.TestHost
	ctx.MTLSIsEnabled = true
	ctx.MTLSHost = "https://matls-example.com"

	// When.
	audiences := ctx.Audiences()

	// Then.
	assert.Contains(t, audiences, ctx.Host)
	assert.Contains(t, audiences, ctx.Host+string(goidc.EndpointToken))
	assert.Contains(t, audiences, ctx.Host+string(goidc.EndpointPushedAuthorizationRequest))
	assert.Contains(t, audiences, ctx.Host+string(goidc.EndpointUserInfo))
	assert.Contains(t, audiences, ctx.MTLSHost)
	assert.Contains(t, audiences, ctx.MTLSHost+string(goidc.EndpointToken))
	assert.Contains(t, audiences, ctx.MTLSHost+string(goidc.EndpointPushedAuthorizationRequest))
	assert.Contains(t, audiences, ctx.MTLSHost+string(goidc.EndpointUserInfo))
}

func TestGetPolicyByID_HappyPath(t *testing.T) {
	// Given.
	policyID := "random_policy_id"
	ctx := utils.OAuthContext{}
	ctx.Policies = append(ctx.Policies, goidc.NewPolicy(policyID, nil, nil))

	// When.
	policy := ctx.Policy(policyID)

	// Then.
	assert.Equal(t, policyID, policy.ID)
}

func TestGetAvailablePolicy_HappyPath(t *testing.T) {

	// Given.
	unavailablePolicy := goidc.NewPolicy(
		"unavailable_policy",
		func(ctx goidc.OAuthContext, c goidc.Client, s *goidc.AuthnSession) bool {
			return false
		},
		nil,
	)
	availablePolicy := goidc.NewPolicy(
		"available_policy",
		func(ctx goidc.OAuthContext, c goidc.Client, s *goidc.AuthnSession) bool {
			return true
		},
		nil,
	)
	ctx := utils.GetTestContext(t)
	ctx.Policies = []goidc.AuthnPolicy{unavailablePolicy, availablePolicy}

	// When.
	policy, policyIsAvailable := ctx.FindAvailablePolicy(goidc.Client{}, &goidc.AuthnSession{})

	// Then.
	require.True(t, policyIsAvailable, "GetPolicy is not fetching any policy")
	assert.Equal(t, policy.ID, availablePolicy.ID, "GetPolicy is not fetching the right policy")
}

func TestGetAvailablePolicy_NoPolicyAvailable(t *testing.T) {
	// Given.
	unavailablePolicy := goidc.NewPolicy(
		"unavailable_policy",
		func(ctx goidc.OAuthContext, c goidc.Client, s *goidc.AuthnSession) bool {
			return false
		},
		nil,
	)
	ctx := utils.GetTestContext(t)
	ctx.Policies = []goidc.AuthnPolicy{unavailablePolicy}

	// When.
	_, policyIsAvailable := ctx.FindAvailablePolicy(goidc.Client{}, &goidc.AuthnSession{})

	// Then.
	require.False(t, policyIsAvailable, "GetPolicy is not fetching any policy")
}

func TestGetClient_WithPublicJWKS(t *testing.T) {
	// Given.
	clientJWK := utils.GetTestPrivatePS256JWK(t, "client_key")
	client := utils.GetTestClient(t)
	client.PublicJWKS = &goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{clientJWK}}
	ctx := utils.GetTestContext(t)
	require.Nil(t, ctx.CreateOrUpdateClient(client))

	// When.
	client, err := ctx.GetClient(client.ID)

	// Then.
	require.Nil(t, err)
	require.NotNil(t, client.PublicJWKS)
	assert.Equal(t, clientJWK.KeyID(), client.PublicJWKS.Keys[0].KeyID())
}

func TestGetClient_WithoutPublicJWKS(t *testing.T) {
	// Given.
	client := utils.GetTestClient(t)
	client.PublicJWKS = nil
	ctx := utils.GetTestContext(t)
	require.Nil(t, ctx.CreateOrUpdateClient(client))

	// When.
	client, err := ctx.GetClient(client.ID)

	// Then.
	require.Nil(t, err)
	assert.NotNil(t, client.PublicJWKS)
}

func TestGetBearerToken_HappyPath(t *testing.T) {
	// Given.
	ctx := utils.OAuthContext{}
	ctx.Request = httptest.NewRequest(http.MethodGet, utils.TestHost, nil)
	ctx.Request.Header.Set("Authorization", "Bearer token")

	// When.
	token, ok := ctx.BearerToken()

	// Then.
	require.True(t, ok)
	assert.Equal(t, "token", token)
}

func TestGetBearerToken_NoToken(t *testing.T) {
	// Given.
	ctx := utils.OAuthContext{}
	ctx.Request = httptest.NewRequest(http.MethodGet, utils.TestHost, nil)

	// When.
	_, ok := ctx.BearerToken()

	// Then.
	require.False(t, ok)
}

func TestGetBearerToken_NotABearerToken(t *testing.T) {
	// Given.
	ctx := utils.OAuthContext{}
	ctx.Request = httptest.NewRequest(http.MethodGet, utils.TestHost, nil)
	ctx.Request.Header.Set("Authorization", "DPoP token")

	// When.
	_, ok := ctx.BearerToken()

	// Then.
	require.False(t, ok)
}

func TestGetAuthorizationToken_HappyPath(t *testing.T) {
	// Given.
	ctx := utils.OAuthContext{}
	ctx.Request = httptest.NewRequest(http.MethodGet, utils.TestHost, nil)
	ctx.Request.Header.Set("Authorization", "Bearer token")

	// When.
	token, tokenType, ok := ctx.AuthorizationToken()

	// Then.
	require.True(t, ok)
	assert.Equal(t, goidc.TokenTypeBearer, tokenType)
	assert.Equal(t, "token", token)
}

func TestGetAuthorizationToken_NoToken(t *testing.T) {
	// Given.
	ctx := utils.OAuthContext{}
	ctx.Request = httptest.NewRequest(http.MethodGet, utils.TestHost, nil)

	// When.
	_, _, ok := ctx.AuthorizationToken()

	// Then.
	require.False(t, ok)
}

func TestAuthorizationToken_InvalidAuthorizationHeader(t *testing.T) {
	// Given.
	ctx := utils.OAuthContext{}
	ctx.Request = httptest.NewRequest(http.MethodGet, utils.TestHost, nil)
	ctx.Request.Header.Set("InvalidAuthorization", "Bearer token")

	// When.
	_, _, ok := ctx.AuthorizationToken()

	// Then.
	require.False(t, ok)
}

func TestHeader_HappyPath(t *testing.T) {
	// Given.
	ctx := utils.OAuthContext{}
	ctx.Request = httptest.NewRequest(http.MethodGet, utils.TestHost, nil)
	ctx.Request.Header.Set("Test-Header", "test_value")

	// When.
	header, ok := ctx.Header("Test-Header")

	// Then.
	require.True(t, ok)
	assert.Equal(t, "test_value", header)
}

func TestSignatureAlgorithms_HappyPath(t *testing.T) {
	// Given.
	signingKey := utils.GetTestPrivateRS256JWKWithUsage(t, "signing_key", goidc.KeyUsageSignature)
	encryptionKey := utils.GetTestPrivatePS256JWKWithUsage(t, "encryption_key", goidc.KeyUsageEncryption)

	ctx := utils.OAuthContext{}
	ctx.PrivateJWKS = goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{signingKey, encryptionKey}}

	// When.
	algorithms := ctx.SignatureAlgorithms()

	// Then.
	require.Len(t, algorithms, 1)
	assert.Contains(t, algorithms, jose.RS256)
}

func TestPublicKeys_HappyPath(t *testing.T) {
	// Given.
	signingKey := utils.GetTestPrivatePS256JWK(t, "signing_key")

	ctx := utils.OAuthContext{}
	ctx.PrivateJWKS = goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{signingKey}}

	// When.
	publicJWKS := ctx.PublicKeys()

	// Then.
	require.Len(t, publicJWKS.Keys, 1)
	publicJWK := publicJWKS.Keys[0]
	assert.Equal(t, "signing_key", publicJWK.KeyID())
	assert.True(t, publicJWK.IsPublic())
}

func TestPublicKey_HappyPath(t *testing.T) {
	// Given.
	signingKey := utils.GetTestPrivatePS256JWK(t, "signing_key")

	ctx := utils.OAuthContext{}
	ctx.PrivateJWKS = goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{signingKey}}

	// When.
	publicJWK, ok := ctx.PublicKey("signing_key")

	// Then.
	require.True(t, ok)
	assert.Equal(t, "signing_key", publicJWK.KeyID())
	assert.True(t, publicJWK.IsPublic())
}

func TestPrivateKey_HappyPath(t *testing.T) {
	// Given.
	signingKey := utils.GetTestPrivatePS256JWK(t, "signing_key")

	ctx := utils.OAuthContext{}
	ctx.PrivateJWKS = goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{signingKey}}

	// When.
	privateJWK, ok := ctx.PrivateKey("signing_key")

	// Then.
	require.True(t, ok)
	assert.Equal(t, "signing_key", privateJWK.KeyID())
	assert.False(t, privateJWK.IsPublic())
}

func TestPrivateKey_KeyDoesntExist(t *testing.T) {
	// Given.
	ctx := utils.OAuthContext{}
	ctx.PrivateJWKS = goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{}}

	// When.
	_, ok := ctx.PrivateKey("signing_key")

	// Then.
	require.False(t, ok)
}

func TestTokenSignatureKey_HappyPath(t *testing.T) {
	// Given.
	signingKeyID := "signing_key"
	signingKey := utils.GetTestPrivatePS256JWK(t, signingKeyID)

	ctx := utils.OAuthContext{}
	ctx.DefaultTokenSignatureKeyID = "random_key"
	ctx.PrivateJWKS = goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{signingKey}}

	// When.
	jwk := ctx.TokenSignatureKey(goidc.NewJWTTokenOptions(signingKeyID, 60, false))

	// Then.
	assert.Equal(t, signingKeyID, jwk.KeyID())
}

func TestTokenSignatureKey_InvalidKeyIDInformed(t *testing.T) {
	// Given.
	signingKeyID := "signing_key"
	signingKey := utils.GetTestPrivatePS256JWK(t, signingKeyID)

	ctx := utils.OAuthContext{}
	ctx.DefaultTokenSignatureKeyID = signingKeyID
	ctx.PrivateJWKS = goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{signingKey}}

	// When.
	jwk := ctx.TokenSignatureKey(goidc.NewJWTTokenOptions("random_key", 60, false))

	// Then.
	assert.Equal(t, signingKeyID, jwk.KeyID())
}

func TestTokenSignatureKey_NoKeyIDInformed(t *testing.T) {
	// Given.
	signingKeyID := "signing_key"
	signingKey := utils.GetTestPrivatePS256JWK(t, signingKeyID)

	ctx := utils.OAuthContext{}
	ctx.DefaultTokenSignatureKeyID = signingKeyID
	ctx.PrivateJWKS = goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{signingKey}}

	// When.
	jwk := ctx.TokenSignatureKey(goidc.TokenOptions{})

	// Then.
	assert.Equal(t, signingKeyID, jwk.KeyID())
}