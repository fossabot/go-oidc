package dcr

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func validateDynamicClientRequest(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	return runValidations(
		ctx, dynamicClient,
		validateAuthnMethod,
		validateClientSignatureAlgorithmForPrivateKeyJWT,
		validateClientSignatureAlgorithmForClientSecretJWT,
		validateJWKSAreRequiredForPrivateKeyJWTAuthn,
		validateJWKSIsRequiredWhenSelfSignedTLSAuthn,
		validateTLSSubjectInfoWhenTLSAuthn,
		validateGrantTypes,
		validateRefreshTokenGrant,
		validateClientCredentialsGrant,
		validateClientAuthnMethodForIntrospectionGrant,
		validateRedirectURIS,
		validateResponseTypes,
		validateCannotRequestImplicitResponseTypeWithoutImplicitGrant,
		validateOpenIDScopeIfRequired,
		validateSubjectIdentifierType,
		validateIDTokenSignatureAlgorithm,
		validateIDTokenEncryptionAlgorithms,
		validateUserInfoSignatureAlgorithm,
		validateUserInfoEncryptionAlgorithms,
		validateJARSignatureAlgorithm,
		validateJAREncryptionAlgorithms,
		validateJARMSignatureAlgorithm,
		validateJARMEncryptionAlgorithms,
		validatePublicJWKS,
		validatePublicJWKSURI,
		validateAuthorizationDetailTypes,
	)
}

func runValidations(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
	validations ...func(
		ctx *oidc.Context,
		dynamicClient dynamicClientRequest,
	) goidc.OAuthError,
) goidc.OAuthError {
	for _, validation := range validations {
		if err := validation(ctx, dynamicClient); err != nil {
			return err
		}
	}
	return nil
}

func validateGrantTypes(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	if !goidc.ContainsAll(ctx.GrantTypes, dynamicClient.GrantTypes...) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "grant type not allowed")
	}
	return nil
}

func validateClientCredentialsGrant(
	_ *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	if dynamicClient.AuthnMethod != goidc.ClientAuthnNone {
		return nil
	}

	if slices.Contains(dynamicClient.GrantTypes, goidc.GrantClientCredentials) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "client_credentials grant type not allowed")
	}

	return nil
}

func validateClientAuthnMethodForIntrospectionGrant(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	if slices.Contains(dynamicClient.GrantTypes, goidc.GrantIntrospection) &&
		!slices.Contains(ctx.IntrospectionClientAuthnMethods, dynamicClient.AuthnMethod) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "client_credentials grant type not allowed")
	}

	return nil
}

func validateRedirectURIS(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	if len(dynamicClient.RedirectURIS) == 0 {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "at least one redirect uri must be informed")
	}
	return nil
}

func validateResponseTypes(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	if !goidc.ContainsAll(ctx.ResponseTypes, dynamicClient.ResponseTypes...) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "response type not allowed")
	}
	return nil
}

func validateCannotRequestImplicitResponseTypeWithoutImplicitGrant(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	containsImplicitResponseType := false
	for _, rt := range dynamicClient.ResponseTypes {
		if rt.IsImplicit() {
			containsImplicitResponseType = true
		}
	}

	if containsImplicitResponseType && !slices.Contains(ctx.GrantTypes, goidc.GrantImplicit) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "implicit grant type is required for implicit response types")
	}
	return nil
}

func validateAuthnMethod(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	if !goidc.ContainsAll(ctx.ClientAuthnMethods, dynamicClient.AuthnMethod) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "authn method not allowed")
	}
	return nil
}

func validateOpenIDScopeIfRequired(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	if !ctx.OpenIDScopeIsRequired {
		return nil
	}

	if dynamicClient.Scopes != "" || !goidc.ScopesContainsOpenID(dynamicClient.Scopes) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "scope openid is required")
	}

	return nil
}

func validateSubjectIdentifierType(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	if dynamicClient.SubjectIdentifierType != "" && !goidc.ContainsAll(ctx.SubjectIdentifierTypes, dynamicClient.SubjectIdentifierType) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "subject_type not supported")
	}
	return nil
}

func validateIDTokenSignatureAlgorithm(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	if dynamicClient.IDTokenSignatureAlgorithm != "" && !goidc.ContainsAll(ctx.UserInfoSignatureAlgorithms(), dynamicClient.IDTokenSignatureAlgorithm) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "id_token_signed_response_alg not supported")
	}
	return nil
}

func validateUserInfoSignatureAlgorithm(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	if dynamicClient.UserInfoSignatureAlgorithm != "" && !goidc.ContainsAll(ctx.UserInfoSignatureAlgorithms(), dynamicClient.UserInfoSignatureAlgorithm) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "id_token_signed_response_alg not supported")
	}
	return nil
}

func validateJARSignatureAlgorithm(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	if dynamicClient.JARSignatureAlgorithm != "" && !goidc.ContainsAll(ctx.JARSignatureAlgorithms, dynamicClient.JARSignatureAlgorithm) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "request_object_signing_alg not supported")
	}
	return nil
}

func validateJARMSignatureAlgorithm(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	if dynamicClient.JARMSignatureAlgorithm != "" && !goidc.ContainsAll(ctx.JARMSignatureAlgorithms(), dynamicClient.JARMSignatureAlgorithm) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "authorization_signed_response_alg not supported")
	}
	return nil
}

func validateClientSignatureAlgorithmForPrivateKeyJWT(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	if dynamicClient.AuthnMethod != goidc.ClientAuthnPrivateKeyJWT {
		return nil
	}

	if dynamicClient.AuthnSignatureAlgorithm != "" && !goidc.ContainsAll(ctx.PrivateKeyJWTSignatureAlgorithms, dynamicClient.AuthnSignatureAlgorithm) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "token_endpoint_auth_signing_alg not supported")
	}
	return nil
}

func validateClientSignatureAlgorithmForClientSecretJWT(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	if dynamicClient.AuthnMethod != goidc.ClientAuthnSecretJWT {
		return nil
	}

	if dynamicClient.AuthnSignatureAlgorithm != "" && !goidc.ContainsAll(ctx.ClientSecretJWTSignatureAlgorithms, dynamicClient.AuthnSignatureAlgorithm) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "token_endpoint_auth_signing_alg not supported")
	}
	return nil
}

func validateJWKSAreRequiredForPrivateKeyJWTAuthn(
	_ *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	if dynamicClient.AuthnMethod != goidc.ClientAuthnPrivateKeyJWT {
		return nil
	}

	if dynamicClient.PublicJWKS == nil && dynamicClient.PublicJWKSURI == "" {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "the jwks is required for private_key_jwt")
	}

	return nil
}

func validateJWKSIsRequiredWhenSelfSignedTLSAuthn(
	_ *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	if dynamicClient.AuthnMethod != goidc.ClientAuthnSelfSignedTLS {
		return nil
	}

	if dynamicClient.PublicJWKSURI == "" && dynamicClient.PublicJWKS == nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "jwks is required when authenticating with self signed certificates")
	}

	return nil
}

func validateTLSSubjectInfoWhenTLSAuthn(
	_ *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	if dynamicClient.AuthnMethod != goidc.ClientAuthnTLS {
		return nil
	}

	numberOfIdentifiers := 0

	if dynamicClient.TLSSubjectDistinguishedName != "" {
		numberOfIdentifiers++
	}

	if dynamicClient.TLSSubjectAlternativeName != "" {
		numberOfIdentifiers++
	}

	if dynamicClient.TLSSubjectAlternativeNameIp != "" {
		numberOfIdentifiers++
	}

	if numberOfIdentifiers != 1 {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "only one of: tls_client_auth_subject_dn, tls_client_auth_san_dns, tls_client_auth_san_ip must be informed")
	}

	return nil
}

func validateIDTokenEncryptionAlgorithms(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	// Return an error if ID token encryption is not enabled, but the client requested it.
	if !ctx.UserInfoEncryptionIsEnabled {
		if dynamicClient.IDTokenKeyEncryptionAlgorithm != "" || dynamicClient.IDTokenContentEncryptionAlgorithm != "" {
			return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "ID token encryption is not supported")
		}
		return nil
	}

	if dynamicClient.IDTokenKeyEncryptionAlgorithm != "" && !slices.Contains(ctx.UserInfoKeyEncryptionAlgorithms, dynamicClient.IDTokenKeyEncryptionAlgorithm) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "id_token_encrypted_response_alg not supported")
	}

	if dynamicClient.IDTokenContentEncryptionAlgorithm != "" && dynamicClient.IDTokenKeyEncryptionAlgorithm == "" {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "id_token_encrypted_response_alg is required if id_token_encrypted_response_enc is informed")
	}

	if dynamicClient.IDTokenContentEncryptionAlgorithm != "" && !slices.Contains(ctx.UserInfoContentEncryptionAlgorithms, dynamicClient.IDTokenContentEncryptionAlgorithm) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "id_token_encrypted_response_enc not supported")
	}

	return nil
}

func validateUserInfoEncryptionAlgorithms(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	// Return an error if user info encryption is not enabled, but the client requested it.
	if !ctx.UserInfoEncryptionIsEnabled {
		if dynamicClient.UserInfoKeyEncryptionAlgorithm != "" || dynamicClient.UserInfoContentEncryptionAlgorithm != "" {
			return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "user info encryption is not supported")
		}
		return nil
	}

	if dynamicClient.UserInfoKeyEncryptionAlgorithm != "" && !slices.Contains(ctx.UserInfoKeyEncryptionAlgorithms, dynamicClient.UserInfoKeyEncryptionAlgorithm) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "userinfo_encrypted_response_alg not supported")
	}

	if dynamicClient.UserInfoContentEncryptionAlgorithm != "" && dynamicClient.UserInfoKeyEncryptionAlgorithm == "" {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "userinfo_encrypted_response_alg is required if userinfo_encrypted_response_enc is informed")
	}

	if dynamicClient.UserInfoContentEncryptionAlgorithm != "" && !slices.Contains(ctx.UserInfoContentEncryptionAlgorithms, dynamicClient.UserInfoContentEncryptionAlgorithm) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "userinfo_encrypted_response_enc not supported")
	}

	return nil
}

func validateJARMEncryptionAlgorithms(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	// Return an error if jarm encryption is not enabled, but the client requested it.
	if !ctx.JARMIsEnabled {
		if dynamicClient.JARMKeyEncryptionAlgorithm != "" || dynamicClient.JARMContentEncryptionAlgorithm != "" {
			return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "jarm encryption is not supported")
		}
		return nil
	}

	if dynamicClient.JARMKeyEncryptionAlgorithm != "" && !slices.Contains(ctx.JARMKeyEncrytionAlgorithms, dynamicClient.JARMKeyEncryptionAlgorithm) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "authorization_encrypted_response_alg not supported")
	}

	if dynamicClient.JARMContentEncryptionAlgorithm != "" && dynamicClient.JARMKeyEncryptionAlgorithm == "" {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "authorization_encrypted_response_alg is required if authorization_encrypted_response_enc is informed")
	}

	if dynamicClient.JARMContentEncryptionAlgorithm != "" && !slices.Contains(ctx.JARMContentEncryptionAlgorithms, dynamicClient.JARMContentEncryptionAlgorithm) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "authorization_encrypted_response_enc not supported")
	}

	return nil
}

func validateJAREncryptionAlgorithms(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	// Return an error if jar encryption is not enabled, but the client requested it.
	if !ctx.JAREncryptionIsEnabled {
		if dynamicClient.JARKeyEncryptionAlgorithm != "" || dynamicClient.JARContentEncryptionAlgorithm != "" {
			return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "jar encryption is not supported")
		}
		return nil
	}

	if dynamicClient.JARKeyEncryptionAlgorithm != "" && !slices.Contains(ctx.JARKeyEncryptionAlgorithms(), dynamicClient.JARKeyEncryptionAlgorithm) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "request_object_encryption_alg not supported")
	}

	if dynamicClient.JARContentEncryptionAlgorithm != "" && dynamicClient.JARKeyEncryptionAlgorithm == "" {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "request_object_encryption_alg is required if request_object_encryption_enc is informed")
	}

	if dynamicClient.JARContentEncryptionAlgorithm != "" && !slices.Contains(ctx.JARContentEncryptionAlgorithms, dynamicClient.JARContentEncryptionAlgorithm) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "request_object_encryption_enc not supported")
	}

	return nil
}

func validatePublicJWKS(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	if dynamicClient.PublicJWKS == nil {
		return nil
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(dynamicClient.PublicJWKS, &jwks); err != nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid jwks")
	}

	for _, jwk := range jwks.Keys {
		if !jwk.IsPublic() || !jwk.Valid() {
			return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("the key with ID: %s jwks is invalid", jwk.KeyID))
		}
	}
	return nil
}

func validatePublicJWKSURI(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	// TODO: validate the client jwks uri.
	return nil
}

func validateAuthorizationDetailTypes(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	if !ctx.AuthorizationDetailsParameterIsEnabled || dynamicClient.AuthorizationDetailTypes == nil {
		return nil
	}

	if goidc.ContainsAll(ctx.AuthorizationDetailTypes, dynamicClient.AuthorizationDetailTypes...) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "authorization detail type not supported")
	}

	return nil
}

func validateRefreshTokenGrant(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) goidc.OAuthError {
	if goidc.ScopesContainsOfflineAccess(dynamicClient.Scopes) && !slices.Contains(dynamicClient.GrantTypes, goidc.GrantRefreshToken) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "refresh_token grant is required for using the scope offline_access")
	}

	return nil
}