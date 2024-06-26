package utils

import (
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/internal/unit"
	"github.com/luikymagno/goidc/pkg/goidc"
)

type ResultChannel struct {
	Result any
	Err    goidc.OAuthError
}

func ExtractJarFromRequestObject(
	ctx Context,
	reqObject string,
	client goidc.Client,
) (
	models.AuthorizationRequest,
	goidc.OAuthError,
) {
	if ctx.JarEncryptionIsEnabled && unit.IsJwe(reqObject) {
		signedReqObject, err := extractSignedRequestObjectFromEncryptedRequestObject(ctx, reqObject, client)
		if err != nil {
			return models.AuthorizationRequest{}, err
		}
		reqObject = signedReqObject
	}

	if !unit.IsJws(reqObject) {
		return models.AuthorizationRequest{}, goidc.NewOAuthError(goidc.InvalidRequest, "the request object is not a JWS")
	}

	return extractJarFromSignedRequestObject(ctx, reqObject, client)
}

func extractSignedRequestObjectFromEncryptedRequestObject(
	ctx Context,
	reqObject string,
	_ goidc.Client,
) (
	string,
	goidc.OAuthError,
) {
	encryptedReqObject, err := jose.ParseEncrypted(reqObject, ctx.GetJarKeyEncryptionAlgorithms(), ctx.JarContentEncryptionAlgorithms)
	if err != nil {
		return "", goidc.NewOAuthError(goidc.InvalidResquestObject, "could not parse the encrypted request object")
	}

	keyId := encryptedReqObject.Header.KeyID
	if keyId == "" {
		return "", goidc.NewOAuthError(goidc.InvalidResquestObject, "invalid JWE key ID")
	}

	jwk, ok := ctx.GetPrivateKey(keyId)
	if !ok || jwk.GetUsage() != string(goidc.KeyEncryptionUsage) {
		return "", goidc.NewOAuthError(goidc.InvalidResquestObject, "invalid JWK used for encryption")
	}

	decryptedReqObject, err := encryptedReqObject.Decrypt(jwk.GetKey())
	if err != nil {
		return "", goidc.NewOAuthError(goidc.InvalidResquestObject, err.Error())
	}

	return string(decryptedReqObject), nil
}

func extractJarFromSignedRequestObject(
	ctx Context,
	reqObject string,
	client goidc.Client,
) (
	models.AuthorizationRequest,
	goidc.OAuthError,
) {
	jarAlgorithms := ctx.JarSignatureAlgorithms
	if client.JarSignatureAlgorithm != "" {
		jarAlgorithms = []jose.SignatureAlgorithm{client.JarSignatureAlgorithm}
	}
	parsedToken, err := jwt.ParseSigned(reqObject, jarAlgorithms)
	if err != nil {
		return models.AuthorizationRequest{}, goidc.NewOAuthError(goidc.InvalidResquestObject, err.Error())
	}

	// Verify that the assertion indicates the key ID.
	if len(parsedToken.Headers) != 1 && parsedToken.Headers[0].KeyID == "" {
		return models.AuthorizationRequest{}, goidc.NewOAuthError(goidc.InvalidResquestObject, "invalid kid header")
	}

	// Verify that the key ID belongs to the client.
	jwk, oauthErr := client.GetJwk(parsedToken.Headers[0].KeyID)
	if oauthErr != nil {
		return models.AuthorizationRequest{}, goidc.NewOAuthError(goidc.InvalidResquestObject, oauthErr.Error())
	}

	var claims jwt.Claims
	var jarReq models.AuthorizationRequest
	if err := parsedToken.Claims(jwk.GetKey(), &claims, &jarReq); err != nil {
		return models.AuthorizationRequest{}, goidc.NewOAuthError(goidc.InvalidResquestObject, "could not extract claims")
	}

	// Validate that the "exp" claims is present and it's not too far in the future.
	if claims.Expiry == nil || int(time.Until(claims.Expiry.Time()).Seconds()) > ctx.JarLifetimeSecs {
		return models.AuthorizationRequest{}, goidc.NewOAuthError(goidc.InvalidResquestObject, "invalid exp claim")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      client.Id,
		AnyAudience: []string{ctx.Host},
	}, time.Duration(0))
	if err != nil {
		return models.AuthorizationRequest{}, goidc.NewOAuthError(goidc.InvalidResquestObject, "invalid claims")
	}

	return jarReq, nil
}

func ValidateDpopJwt(
	ctx Context,
	dpopJwt string,
	expectedDpopClaims models.DpopJwtValidationOptions,
) goidc.OAuthError {
	parsedDpopJwt, err := jwt.ParseSigned(dpopJwt, ctx.DpopSignatureAlgorithms)
	if err != nil {
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid dpop")
	}

	if len(parsedDpopJwt.Headers) != 1 {
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid dpop")
	}

	if parsedDpopJwt.Headers[0].ExtraHeaders["typ"] != "dpop+jwt" {
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid typ header. it should be dpop+jwt")
	}

	jwk := parsedDpopJwt.Headers[0].JSONWebKey
	if jwk == nil || !jwk.Valid() || !jwk.IsPublic() {
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid jwk header")
	}

	var claims jwt.Claims
	var dpopClaims models.DpopJwtClaims
	if err := parsedDpopJwt.Claims(jwk.Key, &claims, &dpopClaims); err != nil {
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid dpop")
	}

	// Validate that the "iat" claim is present and it is not too far in the past.
	if claims.IssuedAt == nil || int(time.Since(claims.IssuedAt.Time()).Seconds()) > ctx.DpopLifetimeSecs {
		return goidc.NewOAuthError(goidc.UnauthorizedClient, "invalid dpop")
	}

	if claims.ID == "" {
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid jti claim")
	}

	if dpopClaims.HttpMethod != ctx.GetRequestMethod() {
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid htm claim")
	}

	// The query and fragment components of the "htu" must be ignored.
	// Also, htu should be case-insensitive.
	httpUri, err := unit.GetUrlWithoutParams(strings.ToLower(dpopClaims.HttpUri))
	if err != nil || !slices.Contains(ctx.GetAudiences(), httpUri) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid htu claim")
	}

	if expectedDpopClaims.AccessToken != "" && dpopClaims.AccessTokenHash != unit.GenerateBase64UrlSha256Hash(expectedDpopClaims.AccessToken) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid ath claim")
	}

	if expectedDpopClaims.JwkThumbprint != "" && unit.GenerateJwkThumbprint(dpopJwt, ctx.DpopSignatureAlgorithms) != expectedDpopClaims.JwkThumbprint {
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid jwk thumbprint")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{}, time.Duration(0))
	if err != nil {
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid dpop")
	}

	return nil
}

func GetValidTokenClaims(
	ctx Context,
	token string,
) (
	map[string]any,
	goidc.OAuthError,
) {
	parsedToken, err := jwt.ParseSigned(token, ctx.GetSignatureAlgorithms())
	if err != nil {
		// If the token is not a valid JWT, we'll treat it as an opaque token.
		return nil, goidc.NewOAuthError(goidc.InvalidRequest, "could not parse the token")
	}

	if len(parsedToken.Headers) != 1 || parsedToken.Headers[0].KeyID == "" {
		return nil, goidc.NewOAuthError(goidc.InvalidRequest, "invalid header kid")
	}

	keyId := parsedToken.Headers[0].KeyID
	publicKey, ok := ctx.GetPublicKey(keyId)
	if !ok || publicKey.GetUsage() != string(goidc.KeySignatureUsage) {
		return nil, goidc.NewOAuthError(goidc.AccessDenied, "invalid token")
	}

	var claims jwt.Claims
	var rawClaims map[string]any
	if err := parsedToken.Claims(publicKey.GetKey(), &claims, &rawClaims); err != nil {
		return nil, goidc.NewOAuthError(goidc.AccessDenied, "invalid token")
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer: ctx.Host,
	}, time.Duration(0)); err != nil {
		return nil, goidc.NewOAuthError(goidc.AccessDenied, "invalid token")
	}

	return rawClaims, nil
}

func GetTokenId(ctx Context, token string) (string, goidc.OAuthError) {
	if !unit.IsJws(token) {
		return token, nil
	}

	claims, err := GetValidTokenClaims(ctx, token)
	if err != nil {
		return "", err
	}

	tokenId := claims[string(goidc.TokenIdClaim)]
	if tokenId == nil {
		return "", goidc.NewOAuthError(goidc.AccessDenied, "invalid token")
	}

	return tokenId.(string), nil
}

func RunValidations(
	ctx Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
	validators ...func(
		ctx Context,
		params goidc.AuthorizationParameters,
		client goidc.Client,
	) goidc.OAuthError,
) goidc.OAuthError {
	for _, validator := range validators {
		if err := validator(ctx, params, client); err != nil {
			return err
		}
	}

	return nil
}

func ExtractProtectedParamsFromForm(ctx Context) map[string]any {
	protectedParams := make(map[string]any)
	for param, value := range ctx.GetFormData() {
		if strings.HasPrefix(param, goidc.ProtectedParamPrefix) {
			protectedParams[param] = value
		}
	}

	return protectedParams
}

func ExtractProtectedParamsFromRequestObject(ctx Context, request string) map[string]any {
	parsedRequest, err := jwt.ParseSigned(request, ctx.JarSignatureAlgorithms)
	if err != nil {
		return map[string]any{}
	}

	var claims map[string]any
	err = parsedRequest.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		return map[string]any{}
	}

	protectedParams := make(map[string]any)
	for param, value := range claims {
		if strings.HasPrefix(param, goidc.ProtectedParamPrefix) {
			protectedParams[param] = value
		}
	}

	return protectedParams
}

func EncryptJwt(
	_ Context,
	jwtString string,
	encryptionJwk goidc.JsonWebKey,
	contentKeyEncryptionAlgorithm jose.ContentEncryption,
) (
	string,
	goidc.OAuthError,
) {
	encrypter, err := jose.NewEncrypter(
		contentKeyEncryptionAlgorithm,
		jose.Recipient{Algorithm: jose.KeyAlgorithm(encryptionJwk.GetAlgorithm()), Key: encryptionJwk.GetKey(), KeyID: encryptionJwk.GetKeyId()},
		(&jose.EncrypterOptions{}).WithType("jwt").WithContentType("jwt"),
	)
	if err != nil {
		return "", goidc.NewOAuthError(goidc.InternalError, err.Error())
	}

	encryptedUserInfoJwtJwe, err := encrypter.Encrypt([]byte(jwtString))
	if err != nil {
		return "", goidc.NewOAuthError(goidc.InternalError, err.Error())
	}

	encryptedUserInfoString, err := encryptedUserInfoJwtJwe.CompactSerialize()
	if err != nil {
		return "", goidc.NewOAuthError(goidc.InternalError, err.Error())
	}

	return encryptedUserInfoString, nil
}

func NewGrantSession(grantOptions goidc.GrantOptions, token models.Token) goidc.GrantSession {
	timestampNow := goidc.GetTimestampNow()
	return goidc.GrantSession{
		Id:                          uuid.New().String(),
		TokenId:                     token.Id,
		JwkThumbprint:               token.JwkThumbprint,
		ClientCertificateThumbprint: token.CertificateThumbprint,
		CreatedAtTimestamp:          timestampNow,
		LastTokenIssuedAtTimestamp:  timestampNow,
		ExpiresAtTimestamp:          timestampNow + grantOptions.TokenExpiresInSecs,
		ActiveScopes:                grantOptions.GrantedScopes,
		GrantOptions:                grantOptions,
	}
}

func NewAuthnSession(authParams goidc.AuthorizationParameters, client goidc.Client) goidc.AuthnSession {
	return goidc.AuthnSession{
		Id:                       uuid.NewString(),
		ClientId:                 client.Id,
		AuthorizationParameters:  authParams,
		CreatedAtTimestamp:       goidc.GetTimestampNow(),
		Store:                    make(map[string]any),
		AdditionalTokenClaims:    make(map[string]any),
		AdditionalIdTokenClaims:  map[string]any{},
		AdditionalUserInfoClaims: map[string]any{},
	}
}
