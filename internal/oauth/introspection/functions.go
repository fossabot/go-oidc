package introspection

import (
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func validateTokenIntrospectionRequest(
	_ *utils.Context,
	req utils.TokenIntrospectionRequest,
	client *goidc.Client,
) goidc.OAuthError {
	if !client.IsGrantTypeAllowed(goidc.GrantIntrospection) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidGrant, "client not allowed to introspect tokens")
	}

	if req.Token == "" {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "token is required")
	}

	return nil
}

func tokenIntrospectionInfo(
	ctx *utils.Context,
	token string,
) utils.TokenIntrospectionInfo {

	if len(token) == goidc.RefreshTokenLength {
		return getRefreshTokenIntrospectionInfo(ctx, token)
	}

	if utils.IsJWS(token) {
		return getJWTTokenIntrospectionInfo(ctx, token)
	}

	return opaqueTokenIntrospectionInfo(ctx, token)
}

func getRefreshTokenIntrospectionInfo(
	ctx *utils.Context,
	token string,
) utils.TokenIntrospectionInfo {
	grantSession, err := ctx.GrantSessionByRefreshToken(token)
	if err != nil {
		return utils.TokenIntrospectionInfo{
			IsActive: false,
		}
	}

	if grantSession.IsRefreshSessionExpired() {
		return utils.TokenIntrospectionInfo{
			IsActive: false,
		}
	}

	return utils.TokenIntrospectionInfo{
		IsActive:                    true,
		Scopes:                      grantSession.GrantedScopes,
		AuthorizationDetails:        grantSession.GrantedAuthorizationDetails,
		ClientID:                    grantSession.ClientID,
		Subject:                     grantSession.Subject,
		ExpiresAtTimestamp:          grantSession.ExpiresAtTimestamp,
		JWKThumbprint:               grantSession.JWKThumbprint,
		ClientCertificateThumbprint: grantSession.ClientCertificateThumbprint,
		AdditionalTokenClaims:       grantSession.AdditionalTokenClaims,
	}
}

func getJWTTokenIntrospectionInfo(
	ctx *utils.Context,
	token string,
) utils.TokenIntrospectionInfo {
	claims, err := utils.ValidClaims(ctx, token)
	if err != nil || claims[goidc.ClaimTokenID] == nil {
		return utils.TokenIntrospectionInfo{
			IsActive: false,
		}
	}

	return tokenIntrospectionInfoByID(ctx, claims[goidc.ClaimTokenID].(string))
}

func opaqueTokenIntrospectionInfo(
	ctx *utils.Context,
	token string,
) utils.TokenIntrospectionInfo {
	return tokenIntrospectionInfoByID(ctx, token)
}

func tokenIntrospectionInfoByID(
	ctx *utils.Context,
	tokenID string,
) utils.TokenIntrospectionInfo {
	grantSession, err := ctx.GrantSessionByTokenID(tokenID)
	if err != nil {
		return utils.TokenIntrospectionInfo{
			IsActive: false,
		}
	}

	if grantSession.HasLastTokenExpired() {
		return utils.TokenIntrospectionInfo{
			IsActive: false,
		}
	}

	return utils.TokenIntrospectionInfo{
		IsActive:                    true,
		Scopes:                      grantSession.ActiveScopes,
		AuthorizationDetails:        grantSession.GrantedAuthorizationDetails,
		ClientID:                    grantSession.ClientID,
		Subject:                     grantSession.Subject,
		ExpiresAtTimestamp:          grantSession.LastTokenIssuedAtTimestamp + grantSession.TokenLifetimeSecs,
		JWKThumbprint:               grantSession.JWKThumbprint,
		ClientCertificateThumbprint: grantSession.ClientCertificateThumbprint,
		AdditionalTokenClaims:       grantSession.AdditionalTokenClaims,
	}
}
