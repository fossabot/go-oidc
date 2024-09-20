package clientutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

const (
	idFormPostParam            = "client_id"
	secretFormPostParam        = "client_secret"
	assertionFormPostParam     = "client_assertion"
	assertionTypeFormPostParam = "client_assertion_type"
)

// Authenticated fetches a client associated to the request and returns it
// if the client is authenticated according to its authentication method.
// This function always returns in case of error an instance of [goidc.Error]
// with error code as [goidc.ErrorCodeInvalidClient].
func Authenticated(
	ctx *oidc.Context,
) (
	*goidc.Client,
	error,
) {
	id, err := extractID(ctx)
	if err != nil {
		return nil, err
	}

	client, err := ctx.Client(id)
	if err != nil {
		return nil, goidc.Errorf(goidc.ErrorCodeInvalidClient,
			"client not found", err)
	}

	if err := authenticate(ctx, client); err != nil {
		return nil, err
	}

	return client, nil
}

func authenticate(
	ctx *oidc.Context,
	client *goidc.Client,
) error {
	switch client.AuthnMethod {
	case goidc.ClientAuthnNone:
		return nil
	case goidc.ClientAuthnSecretPost:
		return authenticateSecretPost(ctx, client)
	case goidc.ClientAuthnSecretBasic:
		return authenticateSecretBasic(ctx, client)
	case goidc.ClientAuthnPrivateKeyJWT:
		return authenticatePrivateKeyJWT(ctx, client)
	case goidc.ClientAuthnSecretJWT:
		return authenticateSecretJWT(ctx, client)
	case goidc.ClientAuthnSelfSignedTLS:
		return authenticateSelfSignedTLSCert(ctx, client)
	case goidc.ClientAuthnTLS:
		return authenticateTLSCert(ctx, client)
	default:
		return goidc.NewError(goidc.ErrorCodeInvalidClient, "invalid authentication method")
	}
}

func authenticateSecretPost(
	ctx *oidc.Context,
	c *goidc.Client,
) error {

	if c.ID != ctx.Request.PostFormValue(idFormPostParam) {
		return goidc.NewError(goidc.ErrorCodeInvalidClient, "invalid client id")
	}

	secret := ctx.Request.PostFormValue(secretFormPostParam)
	if secret == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidClient, "client secret not informed")
	}
	return validateSecret(c, secret)
}

func authenticateSecretBasic(
	ctx *oidc.Context,
	c *goidc.Client,
) error {
	id, secret, ok := ctx.Request.BasicAuth()
	if !ok {
		return goidc.NewError(goidc.ErrorCodeInvalidClient,
			"client basic authentication not informed")
	}

	if c.ID != id {
		return goidc.NewError(goidc.ErrorCodeInvalidClient, "invalid client id")
	}

	return validateSecret(c, secret)
}

func validateSecret(
	client *goidc.Client,
	secret string,
) error {
	err := bcrypt.CompareHashAndPassword([]byte(client.HashedSecret), []byte(secret))
	if err != nil {
		return goidc.Errorf(goidc.ErrorCodeInvalidClient, "invalid client secret", err)
	}
	return nil
}

func authenticatePrivateKeyJWT(
	ctx *oidc.Context,
	c *goidc.Client,
) error {

	assertion, err := assertion(ctx)
	if err != nil {
		return err
	}

	sigAlgs := ctx.PrivateKeyJWTSigAlgs
	if c.AuthnSigAlg != "" {
		sigAlgs = []jose.SignatureAlgorithm{c.AuthnSigAlg}
	}
	parsedAssertion, err := jwt.ParseSigned(assertion, sigAlgs)
	if err != nil {
		return goidc.Errorf(goidc.ErrorCodeInvalidClient,
			"could not parse the client assertion", err)
	}

	// Verify that the assertion has only one header.
	if len(parsedAssertion.Headers) != 1 {
		return goidc.NewError(goidc.ErrorCodeInvalidClient,
			"invalid client assertion header")
	}

	jwk, err := jwkMatchingHeader(ctx, c, parsedAssertion.Headers[0])
	if err != nil {
		return err
	}

	claims := jwt.Claims{}
	if err := parsedAssertion.Claims(jwk.Key, &claims); err != nil {
		return goidc.Errorf(goidc.ErrorCodeInvalidClient,
			"could not parse the client assertion claims", err)
	}

	return areClaimsValid(ctx, c, claims)
}

func jwkMatchingHeader(ctx *oidc.Context, c *goidc.Client, header jose.Header) (jose.JSONWebKey, error) {
	if header.KeyID != "" {
		jwk, err := JWKByKeyID(ctx, c, header.KeyID)
		if err != nil {
			return jose.JSONWebKey{}, goidc.Errorf(goidc.ErrorCodeInvalidClient,
				"could not find the jwk used to sign the assertion that matches the 'kid' header", err)
		}
		return jwk, nil
	}

	jwk, err := JWKByAlg(ctx, c, header.Algorithm)
	if err != nil {
		return jose.JSONWebKey{}, goidc.Errorf(goidc.ErrorCodeInvalidClient,
			"could not find the jwk used to sign the assertion that matches the 'alg' header", err)
	}
	return jwk, nil
}

func authenticateSecretJWT(
	ctx *oidc.Context,
	c *goidc.Client,
) error {
	assertion, err := assertion(ctx)
	if err != nil {
		return err
	}

	sigAlgs := ctx.ClientSecretJWTSigAlgs
	if c.AuthnSigAlg != "" {
		sigAlgs = []jose.SignatureAlgorithm{c.AuthnSigAlg}
	}
	parsedAssertion, err := jwt.ParseSigned(assertion, sigAlgs)
	if err != nil {
		return goidc.Errorf(goidc.ErrorCodeInvalidClient,
			"could not parse the client assertion", err)
	}

	claims := jwt.Claims{}
	if err := parsedAssertion.Claims([]byte(c.Secret), &claims); err != nil {
		return goidc.Errorf(goidc.ErrorCodeInvalidClient,
			"could not parse the client assertion claims", err)
	}

	return areClaimsValid(ctx, c, claims)
}

func assertion(ctx *oidc.Context) (string, error) {
	assertionType := ctx.Request.PostFormValue(assertionTypeFormPostParam)
	if assertionType != string(goidc.AssertionTypeJWTBearer) {
		return "", goidc.NewError(goidc.ErrorCodeInvalidClient,
			"invalid assertion_type")
	}

	assertion := ctx.Request.PostFormValue(assertionFormPostParam)
	if assertion == "" {
		return "", goidc.NewError(goidc.ErrorCodeInvalidClient,
			"client_assertion not informed")
	}

	return assertion, nil
}

func areClaimsValid(
	ctx *oidc.Context,
	client *goidc.Client,
	claims jwt.Claims,
) error {

	if claims.Expiry == nil {
		return goidc.NewError(goidc.ErrorCodeInvalidClient,
			"claim 'exp' is missing in the client assertion")
	}

	if claims.IssuedAt == nil {
		return goidc.NewError(goidc.ErrorCodeInvalidClient,
			"claim 'iat' is missing in the client assertion")
	}

	// Validate that the difference between "iat" and "exp" is not too great.
	secsToExpiry := int(claims.Expiry.Time().Sub(claims.IssuedAt.Time()).Seconds())
	if secsToExpiry > ctx.AssertionLifetimeSecs {
		return goidc.NewError(goidc.ErrorCodeInvalidClient,
			"the assertion has a life time more than allowed")
	}

	err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      client.ID,
		Subject:     client.ID,
		AnyAudience: ctx.Audiences(),
	}, time.Duration(0))
	if err != nil {
		return goidc.Errorf(goidc.ErrorCodeInvalidClient, "invalid assertion", err)
	}
	return nil
}

func authenticateSelfSignedTLSCert(
	ctx *oidc.Context,
	c *goidc.Client,
) error {
	if c.ID != ctx.Request.PostFormValue(idFormPostParam) {
		return goidc.NewError(goidc.ErrorCodeInvalidClient, "invalid client id")
	}

	cert, err := ctx.ClientCert()
	if err != nil {
		return goidc.Errorf(goidc.ErrorCodeInvalidClient,
			"invalid client certificate", err)
	}

	jwk, err := jwkMatchingCert(ctx, c, cert)
	if err != nil {
		return err
	}

	if !comparePublicKeys(jwk.Key, cert.PublicKey) {
		return goidc.NewError(goidc.ErrorCodeInvalidClient,
			"the public key in the client certificate and ")
	}

	return nil
}

func jwkMatchingCert(
	ctx *oidc.Context,
	c *goidc.Client,
	cert *x509.Certificate,
) (
	jose.JSONWebKey,
	error,
) {
	jwks, err := c.FetchPublicJWKS(ctx.HTTPClient())
	if err != nil {
		return jose.JSONWebKey{}, goidc.Errorf(goidc.ErrorCodeInternalError,
			"could not load the client JWKS", err)
	}

	for _, jwk := range jwks.Keys {
		if string(jwk.CertificateThumbprintSHA256) == hashSHA256(cert.Raw) ||
			string(jwk.CertificateThumbprintSHA1) == hashSHA1(cert.Raw) {
			return jwk, nil
		}
	}

	return jose.JSONWebKey{}, goidc.NewError(goidc.ErrorCodeInvalidClient,
		"could not find a JWK matching the client certificate")
}

func authenticateTLSCert(
	ctx *oidc.Context,
	c *goidc.Client,
) error {
	if c.ID != ctx.Request.PostFormValue(idFormPostParam) {
		return goidc.NewError(goidc.ErrorCodeInvalidClient, "invalid client id")
	}

	cert, err := ctx.ClientCert()
	if err != nil {
		return goidc.Errorf(goidc.ErrorCodeInvalidClient,
			"invalid client certificate", err)
	}

	switch {
	case c.TLSSubDistinguishedName != "":
		if c.TLSSubDistinguishedName != cert.Subject.String() {
			return goidc.NewError(goidc.ErrorCodeInvalidClient, "invalid distinguished name")
		}
	case c.TLSSubAlternativeName != "":
		if !slices.Contains(cert.DNSNames, c.TLSSubAlternativeName) {
			return goidc.NewError(goidc.ErrorCodeInvalidClient, "invalid alternative name")
		}
	default:
		return goidc.NewError(goidc.ErrorCodeInvalidClient, "client is missing attributes for tls authn")
	}

	return nil
}

// extractID extracts a client ID from the request.
// It looks to all places where an ID can be informed such as the basic
// authentication header and the post form field 'client_id'.
// If different client IDs are found in the request, it returns an error.
func extractID(
	ctx *oidc.Context,
) (
	string,
	error,
) {
	ids := []string{}

	postID := ctx.Request.PostFormValue(idFormPostParam)
	if postID != "" {
		ids = append(ids, postID)
	}

	basicID, _, _ := ctx.Request.BasicAuth()
	if basicID != "" {
		ids = append(ids, basicID)
	}

	assertion := ctx.Request.PostFormValue(assertionFormPostParam)
	if assertion != "" {
		assertionID, err := assertionClientID(assertion,
			ctx.ClientAuthnSigAlgs())
		if err != nil {
			return "", err
		}
		ids = append(ids, assertionID)
	}

	// All the client IDs present must be equal.
	if len(ids) == 0 || !allEquals(ids) {
		return "", goidc.NewError(goidc.ErrorCodeInvalidClient, "invalid client id")
	}

	return ids[0], nil
}

func assertionClientID(
	assertion string,
	sigAlgs []jose.SignatureAlgorithm,
) (
	string,
	error,
) {
	parsedAssertion, err := jwt.ParseSigned(assertion, sigAlgs)
	if err != nil {
		return "", goidc.Errorf(goidc.ErrorCodeInvalidClient,
			"could not parse the client assertion", err)
	}

	var claims map[string]any
	if err := parsedAssertion.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return "", goidc.Errorf(goidc.ErrorCodeInvalidClient,
			"could not parse the client assertion claims", err)
	}

	// The issuer claim is supposed to be the client ID.
	clientID, ok := claims[goidc.ClaimIssuer]
	if !ok {
		return "", goidc.NewError(goidc.ErrorCodeInvalidClient,
			"invalid claim 'iss' in the client assertion")
	}

	clientIDAsString, ok := clientID.(string)
	if !ok {
		return "", goidc.NewError(goidc.ErrorCodeInvalidClient,
			"invalid claim 'iss' in the client assertion")
	}

	return clientIDAsString, nil
}

// Return true only if all the elements in values are equal.
func allEquals[T comparable](values []T) bool {
	if len(values) == 0 {
		return true
	}

	return all(
		values,
		func(value T) bool {
			return value == values[0]
		},
	)
}

// Return true if all the elements in the slice respect the condition.
func all[T interface{}](slice []T, condition func(T) bool) bool {
	for _, element := range slice {
		if !condition(element) {
			return false
		}
	}

	return true
}

func comparePublicKeys(k1 any, k2 any) bool {
	key2, ok := k2.(crypto.PublicKey)
	if !ok {
		return false
	}

	switch key1 := k1.(type) {
	case ed25519.PublicKey:
		return key1.Equal(key2)
	case *ecdsa.PublicKey:
		return key1.Equal(key2)
	case *rsa.PublicKey:
		return key1.Equal(key2)
	default:
		return false
	}
}

func hashSHA256(s []byte) string {
	hash := sha256.New()
	hash.Write([]byte(s))
	return string(hash.Sum(nil))
}

func hashSHA1(s []byte) string {
	hash := sha1.New()
	hash.Write([]byte(s))
	return string(hash.Sum(nil))
}
