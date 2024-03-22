package utils

import (
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func PushAuthorization(ctx Context, req models.PARRequest) (requestUri string, err error) {

	// Authenticate the client as in the token endpoint.
	client, err := getAuthenticatedClient(ctx.CrudManager.ClientManager, models.ClientAuthnContext{
		ClientId:     req.ClientId,
		ClientSecret: req.ClientSecret,
	})
	if err != nil {
		return "", err
	}

	if err = validatePushedAuthorizationParams(client, req); err != nil {
		return "", err
	}

	requestUri = unit.GenerateRequestUri()
	ctx.CrudManager.AuthnSessionManager.CreateOrUpdate(models.AuthnSession{
		Id:                 uuid.NewString(),
		RequestUri:         requestUri,
		ClientId:           client.Id,
		Scopes:             strings.Split(req.Scope, " "),
		RedirectUri:        req.RedirectUri,
		State:              req.State,
		CreatedAtTimestamp: unit.GetTimestampNow(),
	})
	return requestUri, nil
}

func validatePushedAuthorizationParams(client models.Client, req models.PARRequest) error {
	if req.RequestUri != "" {
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "the client must not send a redirect_uri during PAR",
		}
	}

	// The PAR request should accept the same params as the authorize request.
	err := validateAuthorizeParams(client, req.ToAuthorizeRequest())

	// Convert redirection errors to json.
	var redirectErr issues.RedirectError
	if errors.As(err, &redirectErr) {
		return issues.JsonError{
			ErrorCode:        redirectErr.ErrorCode,
			ErrorDescription: redirectErr.ErrorDescription,
		}
	}

	return err
}
