package main

import (
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/examples/authutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

func main() {
	// Get the file path of the source file.
	_, filename, _, _ := runtime.Caller(0)
	sourceDir := filepath.Dir(filename)

	templatesDirPath := filepath.Join(sourceDir, "../templates")

	jwksFilePath := filepath.Join(sourceDir, "../keys/server.jwks")
	serverCertFilePath := filepath.Join(sourceDir, "../keys/server.cert")
	serverCertKeyFilePath := filepath.Join(sourceDir, "../keys/server.key")

	serverKeyID := "rs256_key"
	// Create and configure the OpenID provider.
	op, err := provider.New(
		goidc.ProfileOpenID,
		authutil.Issuer,
		authutil.PrivateJWKS(jwksFilePath),
		provider.WithScopes(authutil.Scopes...),
		provider.WithUserInfoSignatureKeyIDs(serverKeyID),
		provider.WithPAR(),
		provider.WithJAR(jose.RS256),
		provider.WithJARM(serverKeyID),
		provider.WithTokenAuthnMethods(
			goidc.ClientAuthnSecretBasic,
			goidc.ClientAuthnSecretPost,
			goidc.ClientAuthnPrivateKeyJWT,
		),
		provider.WithPrivateKeyJWTSignatureAlgs(jose.RS256),
		provider.WithIssuerResponseParameter(),
		provider.WithClaimsParameter(),
		provider.WithPKCE(goidc.CodeChallengeMethodSHA256),
		provider.WithImplicitGrant(),
		provider.WithAuthorizationCodeGrant(),
		provider.WithRefreshTokenGrant(authutil.IssueRefreshToken),
		provider.WithRefreshTokenLifetime(6000),
		provider.WithClaims(goidc.ClaimEmail, goidc.ClaimEmailVerified),
		provider.WithACRs(goidc.ACRMaceIncommonIAPBronze, goidc.ACRMaceIncommonIAPSilver),
		provider.WithDCR(authutil.DCRFunc, authutil.ValidateInitialTokenFunc),
		provider.WithTokenOptions(authutil.TokenOptionsFunc(serverKeyID)),
		provider.WithHTTPClientFunc(authutil.HTTPClient),
		provider.WithPolicy(authutil.Policy(templatesDirPath)),
		provider.WithHandleErrorFunc(authutil.ErrorLoggingFunc),
		provider.WithRenderErrorFunc(authutil.RenderError(templatesDirPath)),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Set up the server.
	mux := http.NewServeMux()
	handler := op.Handler()

	hostURL, _ := url.Parse(authutil.Issuer)
	// Remove the port from the host name if any.
	host := strings.Split(hostURL.Host, ":")[0]
	mux.Handle(host+"/", handler)

	server := &http.Server{
		Addr:    authutil.Port,
		Handler: mux,
	}
	if err := server.ListenAndServeTLS(serverCertFilePath, serverCertKeyFilePath); err != nil {
		log.Fatal(err)
	}
}
