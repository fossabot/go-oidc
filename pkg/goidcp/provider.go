package goidcp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/goidc/internal/api"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

type TLSOptions struct {
	TLSAddress        string
	ServerCertificate string
	ServerKey         string
	CipherSuites      []uint16
	// The fields below will be used only if mtls is enalbed.
	MTLSAddress                    string
	CaCertificatePool              *x509.CertPool
	UnsecureCertificatesAreAllowed bool
}

type Provider struct {
	config utils.Configuration
}

// TODO: Make it smaller.
func New(
	host string,
	clientManager goidc.ClientManager,
	authnSessionManager goidc.AuthnSessionManager,
	grantSessionManager goidc.GrantSessionManager,
	privateJWKS goidc.JSONWebKeySet,
	defaultTokenKeyID string,
	defaultIDTokenKeyID string,
) *Provider {
	p := &Provider{
		config: utils.Configuration{
			Host:                host,
			Profile:             goidc.ProfileOpenID,
			ClientManager:       clientManager,
			AuthnSessionManager: authnSessionManager,
			GrantSessionManager: grantSessionManager,
			OAuthScopes:         []goidc.Scope{goidc.ScopeOpenID},
			TokenOptions: func(client *goidc.Client, scopes string) (goidc.TokenOptions, error) {
				return goidc.TokenOptions{
					TokenLifetimeSecs: goidc.DefaultTokenLifetimeSecs,
					TokenFormat:       goidc.TokenFormatJWT,
				}, nil
			},
			PrivateJWKS:                   privateJWKS,
			DefaultTokenSignatureKeyID:    defaultTokenKeyID,
			DefaultUserInfoSignatureKeyID: defaultIDTokenKeyID,
			UserInfoSignatureKeyIDs:       []string{defaultIDTokenKeyID},
			IDTokenExpiresInSecs:          600,
			UserClaims:                    []string{},
			GrantTypes: []goidc.GrantType{
				goidc.GrantAuthorizationCode,
			},
			ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
			ResponseModes: []goidc.ResponseMode{
				goidc.ResponseModeQuery,
				goidc.ResponseModeFragment,
				goidc.ResponseModeFormPost,
			},
			ClientAuthnMethods:               []goidc.ClientAuthnType{},
			DPoPSignatureAlgorithms:          []jose.SignatureAlgorithm{},
			SubjectIdentifierTypes:           []goidc.SubjectIdentifierType{goidc.SubjectIdentifierPublic},
			ClaimTypes:                       []goidc.ClaimType{goidc.ClaimTypeNormal},
			AuthenticationSessionTimeoutSecs: goidc.DefaultAuthenticationSessionTimeoutSecs,
			CorrelationIDHeader:              goidc.HeaderCorrelationID,
		},
	}

	return p
}

func (p *Provider) SetSupportedUserClaims(claims ...string) {
	p.config.UserClaims = claims
}

// AddUserInfoSignatureKeyIDs makes more keys available to sign the user info endpoint response and ID tokens.
// There should be at most one per algorithm, in other words, there shouldn't be two key IDs that point to two keys that have the same algorithm.
// This is because clients can choose signing keys per algorithm, e.g. a client can choose the key to sign its ID tokens with the attribute "id_token_signed_response_alg".
func (p *Provider) AddUserInfoSignatureKeyIDs(userInfoSignatureKeyIDs ...string) {
	if !goidc.ContainsAll(userInfoSignatureKeyIDs, p.config.DefaultUserInfoSignatureKeyID) {
		userInfoSignatureKeyIDs = append(userInfoSignatureKeyIDs, p.config.DefaultUserInfoSignatureKeyID)
	}
	p.config.UserInfoSignatureKeyIDs = userInfoSignatureKeyIDs
}

func (p *Provider) SetIDTokenLifetime(idTokenLifetimeSecs int) {
	p.config.IDTokenExpiresInSecs = idTokenLifetimeSecs
}

// EnableUserInfoEncryption allows encryption of ID tokens and of the user info endpoint response.
func (p *Provider) EnableUserInfoEncryption(
	keyEncryptionAlgorithms []goidc.KeyEncryptionAlgorithm,
	contentEncryptionAlgorithms []goidc.ContentEncryptionAlgorithm,
) {
	p.config.UserInfoEncryptionIsEnabled = true

	for _, keyAlg := range keyEncryptionAlgorithms {
		p.config.UserInfoKeyEncryptionAlgorithms = append(
			p.config.UserInfoKeyEncryptionAlgorithms,
			jose.KeyAlgorithm(keyAlg),
		)
	}

	for _, contentAlg := range contentEncryptionAlgorithms {
		p.config.UserInfoContentEncryptionAlgorithms = append(
			p.config.UserInfoContentEncryptionAlgorithms,
			jose.ContentEncryption(contentAlg),
		)
	}
}

// EnableDynamicClientRegistration allows clients to be registered dynamically.
// The dcrPlugin is executed during registration and update of the client to perform
// custom validations (e.g. validate a custom property) or set default values (set the default scopes).
func (p *Provider) EnableDynamicClientRegistration(
	dcrPlugin goidc.DCRPluginFunc,
	shouldRotateTokens bool,
) {
	p.config.DCRIsEnabled = true
	p.config.DCRPlugin = dcrPlugin
	p.config.ShouldRotateRegistrationTokens = shouldRotateTokens

}

// EnableRefreshTokenGrantType makes available the refresh token grant.
// If set to true, shouldRotateTokens will cause a new refresh token to be issued each time
// one is used. The one used during the request then becomes invalid.
func (p *Provider) EnableRefreshTokenGrantType(
	refreshTokenLifetimeSecs int,
	shouldRotateTokens bool,
) {
	p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantRefreshToken)
	p.config.RefreshTokenLifetimeSecs = refreshTokenLifetimeSecs
	p.config.ShouldRotateRefreshTokens = shouldRotateTokens
}

// RequireOpenIDScope forces the openid scope in all requests.
func (p *Provider) RequireOpenIDScope() {
	p.config.OpenIDScopeIsRequired = true
}

// SetTokenOptions defines how access tokens are issued.
func (p *Provider) SetTokenOptions(getTokenOpts goidc.TokenOptionsFunc) {
	p.config.TokenOptions = getTokenOpts
}

// EnableImplicitGrantType allows the implicit grant type and the associated response types.
func (p *Provider) EnableImplicitGrantType() {
	p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantImplicit)
	p.config.ResponseTypes = append(
		p.config.ResponseTypes,
		goidc.ResponseTypeToken,
		goidc.ResponseTypeIDToken,
		goidc.ResponseTypeIDTokenAndToken,
		goidc.ResponseTypeCodeAndIDToken,
		goidc.ResponseTypeCodeAndToken,
		goidc.ResponseTypeCodeAndIDTokenAndToken,
	)
}

func (p *Provider) SetScopes(scopes ...goidc.Scope) {
	// The scope openid is required to be among the scopes.
	if goidc.Scopes(scopes).ContainsOpenID() {
		p.config.OAuthScopes = scopes
	} else {
		p.config.OAuthScopes = append(scopes, goidc.ScopeOpenID)
	}
}

// EnablePushedAuthorizationRequests allows authorization flows to start at the /par endpoint.
func (p *Provider) EnablePushedAuthorizationRequests(parLifetimeSecs int) {
	p.config.ParLifetimeSecs = parLifetimeSecs
	p.config.PARIsEnabled = true
}

// RequirePushedAuthorizationRequests forces authorization flows to start at the /par endpoint.
func (p *Provider) RequirePushedAuthorizationRequests(parLifetimeSecs int) {
	p.EnablePushedAuthorizationRequests(parLifetimeSecs)
	p.config.PARIsRequired = true
}

func (p *Provider) EnableJWTSecuredAuthorizationRequests(
	jarLifetimeSecs int,
	jarAlgorithms ...goidc.SignatureAlgorithm,
) {
	p.config.JARIsEnabled = true
	p.config.JARLifetimeSecs = jarLifetimeSecs
	for _, jarAlgorithm := range jarAlgorithms {
		p.config.JARSignatureAlgorithms = append(
			p.config.JARSignatureAlgorithms,
			jose.SignatureAlgorithm(jarAlgorithm),
		)
	}
}

// RequireJWTSecuredAuthorizationRequests makes JAR required.
func (p *Provider) RequireJWTSecuredAuthorizationRequests(
	jarLifetimeSecs int,
	jarAlgorithms ...goidc.SignatureAlgorithm,
) {
	p.EnableJWTSecuredAuthorizationRequests(jarLifetimeSecs, jarAlgorithms...)
	p.config.JARIsRequired = true
}

func (p *Provider) EnableJWTSecuredAuthorizationRequestEncryption(
	keyEncryptionIDs []string,
	contentEncryptionAlgorithms []jose.ContentEncryption,
) {
	p.config.JAREncryptionIsEnabled = true
	p.config.JARKeyEncryptionIDs = keyEncryptionIDs
	p.config.JARContentEncryptionAlgorithms = contentEncryptionAlgorithms
}

// EnableJWTSecuredAuthorizationResponseMode makes available JARM and the associated response modes.
func (p *Provider) EnableJWTSecuredAuthorizationResponseMode(
	jarmLifetimeSecs int,
	defaultJARMSignatureKeyID string,
	jarmSignatureKeyIDs ...string,
) {
	if !goidc.ContainsAll(jarmSignatureKeyIDs, defaultJARMSignatureKeyID) {
		jarmSignatureKeyIDs = append(jarmSignatureKeyIDs, defaultJARMSignatureKeyID)
	}

	p.config.JARMIsEnabled = true
	p.config.ResponseModes = append(
		p.config.ResponseModes,
		goidc.ResponseModeJWT,
		goidc.ResponseModeQueryJWT,
		goidc.ResponseModeFragmentJWT,
		goidc.ResponseModeFormPostJWT,
	)
	p.config.JARMLifetimeSecs = jarmLifetimeSecs
	p.config.DefaultJARMSignatureKeyID = defaultJARMSignatureKeyID
	p.config.JARMSignatureKeyIDs = jarmSignatureKeyIDs
}

func (p *Provider) EnableJWTSecuredAuthorizationResponseModeEncryption(
	keyEncryptionAlgorithms []goidc.KeyEncryptionAlgorithm,
	contentEncryptionAlgorithms []goidc.ContentEncryptionAlgorithm,
) {
	p.config.JARMEncryptionIsEnabled = true

	for _, keyAlg := range keyEncryptionAlgorithms {
		p.config.JARMKeyEncrytionAlgorithms = append(
			p.config.JARMKeyEncrytionAlgorithms,
			jose.KeyAlgorithm(keyAlg),
		)
	}

	for _, contentAlg := range contentEncryptionAlgorithms {
		p.config.JARMContentEncryptionAlgorithms = append(
			p.config.JARMContentEncryptionAlgorithms,
			jose.ContentEncryption(contentAlg),
		)
	}
}

func (p *Provider) EnableBasicSecretClientAuthn() {
	p.config.ClientAuthnMethods = append(
		p.config.ClientAuthnMethods,
		goidc.ClientAuthnSecretBasic,
	)
}

func (p *Provider) EnableSecretPostClientAuthn() {
	p.config.ClientAuthnMethods = append(
		p.config.ClientAuthnMethods,
		goidc.ClientAuthnSecretPost,
	)
}

func (p *Provider) EnablePrivateKeyJWTClientAuthn(
	assertionLifetimeSecs int,
	signatureAlgorithms ...goidc.SignatureAlgorithm,
) {
	p.config.ClientAuthnMethods = append(p.config.ClientAuthnMethods, goidc.ClientAuthnPrivateKeyJWT)
	p.config.PrivateKeyJWTAssertionLifetimeSecs = assertionLifetimeSecs
	for _, signatureAlgorithm := range signatureAlgorithms {
		p.config.PrivateKeyJWTSignatureAlgorithms = append(
			p.config.PrivateKeyJWTSignatureAlgorithms,
			jose.SignatureAlgorithm(signatureAlgorithm),
		)
	}
}

func (p *Provider) EnableClientSecretJWTAuthn(
	assertionLifetimeSecs int,
	signatureAlgorithms ...goidc.SignatureAlgorithm,
) {
	p.config.ClientAuthnMethods = append(p.config.ClientAuthnMethods, goidc.ClientAuthnSecretBasic)
	p.config.ClientSecretJWTAssertionLifetimeSecs = assertionLifetimeSecs
	for _, signatureAlgorithm := range signatureAlgorithms {
		p.config.ClientSecretJWTSignatureAlgorithms = append(
			p.config.ClientSecretJWTSignatureAlgorithms,
			jose.SignatureAlgorithm(signatureAlgorithm),
		)
	}
}

func (p *Provider) EnableTLSClientAuthn() {
	p.config.ClientAuthnMethods = append(p.config.ClientAuthnMethods, goidc.ClientAuthnTLS)
}

func (p *Provider) EnableSelfSignedTLSClientAuthn() {
	p.config.ClientAuthnMethods = append(p.config.ClientAuthnMethods, goidc.ClientAuthnSelfSignedTLS)
}

func (p *Provider) EnableMTLS(mtlsHost string) {
	p.config.MTLSIsEnabled = true
	p.config.MTLSHost = mtlsHost
}

func (p *Provider) EnableTLSBoundTokens() {
	p.config.TLSBoundTokensIsEnabled = true
}

func (p *Provider) EnableNoneClientAuthn() {
	p.config.ClientAuthnMethods = append(p.config.ClientAuthnMethods, goidc.ClientAuthnNone)
}

func (p *Provider) EnableIssuerResponseParameter() {
	p.config.IssuerResponseParameterIsEnabled = true
}

func (p *Provider) EnableClaimsParameter() {
	p.config.ClaimsParameterIsEnabled = true
}

func (p *Provider) EnableAuthorizationDetailsParameter(types ...string) {
	p.config.AuthorizationDetailsParameterIsEnabled = true
	p.config.AuthorizationDetailTypes = types
}

func (p *Provider) EnableDemonstrationProofOfPossesion(
	dpopLifetimeSecs int,
	dpopSigningAlgorithms ...goidc.SignatureAlgorithm,
) {
	p.config.DPoPIsEnabled = true
	p.config.DPoPLifetimeSecs = dpopLifetimeSecs
	for _, signatureAlgorithm := range dpopSigningAlgorithms {
		p.config.DPoPSignatureAlgorithms = append(
			p.config.DPoPSignatureAlgorithms,
			jose.SignatureAlgorithm(signatureAlgorithm),
		)
	}

}

func (p *Provider) RequireDemonstrationProofOfPossesion(
	dpopLifetimeSecs int,
	dpopSigningAlgorithms ...goidc.SignatureAlgorithm,
) {
	p.EnableDemonstrationProofOfPossesion(dpopLifetimeSecs, dpopSigningAlgorithms...)
	p.config.DPoPIsRequired = true
}

// RequireSenderConstrainedTokens will make at least one sender constraining mechanism (TLS or DPoP) be required,
// in order to issue an access token to a client.
func (p *Provider) RequireSenderConstrainedTokens() {
	p.config.SenderConstrainedTokenIsRequired = true
}

func (p *Provider) EnableTokenIntrospection(
	clientAuthnMethods ...goidc.ClientAuthnType,
) {
	p.config.IntrospectionIsEnabled = true
	p.config.IntrospectionClientAuthnMethods = clientAuthnMethods
	p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantIntrospection)
}

// EnableProofKeyForCodeExchange makes PKCE available to clients.
func (p *Provider) EnableProofKeyForCodeExchange(
	codeChallengeMethods ...goidc.CodeChallengeMethod,
) {
	p.config.CodeChallengeMethods = codeChallengeMethods
	p.config.PkceIsEnabled = true
}

// RequireProofKeyForCodeExchange makes PCKE required.
func (p *Provider) RequireProofKeyForCodeExchange(
	codeChallengeMethods ...goidc.CodeChallengeMethod,
) {
	p.EnableProofKeyForCodeExchange(codeChallengeMethods...)
	p.config.PkceIsRequired = true
}

func (p *Provider) SetSupportedAuthenticationContextReferences(
	acrValues ...goidc.AuthenticationContextReference,
) {
	p.config.AuthenticationContextReferences = acrValues
}

func (p *Provider) SetDisplayValuesSupported(values ...goidc.DisplayValue) {
	p.config.DisplayValues = values
}

func (p *Provider) SetClaimTypesSupported(types ...goidc.ClaimType) {
	p.config.ClaimTypes = types
}

// SetAuthenticationSessionTimeout sets the user authentication session lifetime.
func (p *Provider) SetAuthenticationSessionTimeout(timeoutSecs int) {
	p.config.AuthenticationSessionTimeoutSecs = timeoutSecs
}

// SetHeaderCorrelationID sets the header expected to have the correlation ID
// that will be used for all requests to the server.
func (p *Provider) SetHeaderCorrelationID(header string) {
	p.config.CorrelationIDHeader = header
}

// SetProfileFAPI2 defines the OpenID Provider profile as FAPI 2.0.
// The server will only be able to run if it is configured respecting the
// FAPI 2.0 profile.
// This will also change some of the behavior of the server during runtime to
// be compliant with the FAPI 2.0.
func (p *Provider) SetProfileFAPI2() {
	p.config.Profile = goidc.ProfileFAPI2
}

// AddClient creates or updates a static client.
func (p *Provider) AddClient(client *goidc.Client) error {
	// TODO: This is creating the client at every reload.
	return p.config.ClientManager.CreateOrUpdate(context.Background(), client)
}

// AddPolicy adds an authentication policy that will be evaluated at runtime
// and then executed if selected.
func (p *Provider) AddPolicy(policy goidc.AuthnPolicy) {
	p.config.Policies = append(p.config.Policies, policy)
}

func (p *Provider) Run(
	address string,
	middlewares ...api.WrapHandlerFunc,
) error {
	if err := p.validateConfiguration(); err != nil {
		return err
	}

	handler := p.Handler()
	for _, wrapHandler := range middlewares {
		handler = wrapHandler(handler)
	}
	handler = api.NewCorrelationIDMiddleware(
		handler,
		p.config.CorrelationIDHeader,
	)
	handler = api.NewCacheControlMiddleware(handler)
	return http.ListenAndServe(address, handler)
}

func (p *Provider) RunTLS(
	config TLSOptions,
	middlewares ...api.WrapHandlerFunc,
) error {

	if err := p.validateConfiguration(); err != nil {
		return err
	}

	if p.config.MTLSIsEnabled {
		go func() {
			if err := p.runMTLS(config); err != nil {
				// TODO: Find a way to handle this.
				panic(err)
			}
		}()
	}

	handler := p.Handler()
	for _, wrapHandler := range middlewares {
		handler = wrapHandler(handler)
	}
	handler = api.NewCorrelationIDMiddleware(
		handler,
		p.config.CorrelationIDHeader,
	)
	handler = api.NewCacheControlMiddleware(handler)
	server := &http.Server{
		Addr:    config.TLSAddress,
		Handler: handler,
		TLSConfig: &tls.Config{
			CipherSuites: config.CipherSuites,
		},
	}
	return server.ListenAndServeTLS(config.ServerCertificate, config.ServerKey)
}

func (p *Provider) runMTLS(config TLSOptions) error {

	handler := p.mtlsHandler()
	handler = api.NewCorrelationIDMiddleware(
		handler,
		p.config.CorrelationIDHeader,
	)
	handler = api.NewCacheControlMiddleware(handler)
	handler = api.NewClientCertificateMiddleware(handler)

	tlsClientAuthnType := tls.RequireAndVerifyClientCert
	if config.CaCertificatePool == nil || config.UnsecureCertificatesAreAllowed {
		tlsClientAuthnType = tls.RequireAnyClientCert
	}

	server := &http.Server{
		Addr:    config.MTLSAddress,
		Handler: handler,
		TLSConfig: &tls.Config{
			ClientCAs:    config.CaCertificatePool,
			ClientAuth:   tlsClientAuthnType,
			CipherSuites: config.CipherSuites,
		},
	}
	return server.ListenAndServeTLS(config.ServerCertificate, config.ServerKey)
}

func (p *Provider) Handler() http.Handler {

	serverHandler := http.NewServeMux()

	serverHandler.HandleFunc(
		"GET "+string(goidc.EndpointJSONWebKeySet),
		func(w http.ResponseWriter, r *http.Request) {
			api.HandleJWKSRequest(utils.NewContext(p.config, r, w))
		},
	)

	if p.config.PARIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(goidc.EndpointPushedAuthorizationRequest),
			func(w http.ResponseWriter, r *http.Request) {
				api.HandleParRequest(utils.NewContext(p.config, r, w))
			},
		)
	}

	serverHandler.HandleFunc(
		"GET "+string(goidc.EndpointAuthorization),
		func(w http.ResponseWriter, r *http.Request) {
			api.HandleAuthorizeRequest(utils.NewContext(p.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"POST "+string(goidc.EndpointAuthorization)+"/{callback}",
		func(w http.ResponseWriter, r *http.Request) {
			api.HandleAuthorizeCallbackRequest(
				utils.NewContext(p.config, r, w),
			)
		},
	)

	serverHandler.HandleFunc(
		"POST "+string(goidc.EndpointToken),
		func(w http.ResponseWriter, r *http.Request) {
			api.HandleTokenRequest(utils.NewContext(p.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"GET "+string(goidc.EndpointWellKnown),
		func(w http.ResponseWriter, r *http.Request) {
			api.HandleWellKnownRequest(utils.NewContext(p.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"GET "+string(goidc.EndpointUserInfo),
		func(w http.ResponseWriter, r *http.Request) {
			api.HandleUserInfoRequest(utils.NewContext(p.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"POST "+string(goidc.EndpointUserInfo),
		func(w http.ResponseWriter, r *http.Request) {
			api.HandleUserInfoRequest(utils.NewContext(p.config, r, w))
		},
	)

	if p.config.DCRIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(goidc.EndpointDynamicClient),
			func(w http.ResponseWriter, r *http.Request) {
				api.HandleDynamicClientCreation(utils.NewContext(p.config, r, w))
			},
		)

		serverHandler.HandleFunc(
			"PUT "+string(goidc.EndpointDynamicClient)+"/{client_id}",
			func(w http.ResponseWriter, r *http.Request) {
				api.HandleDynamicClientUpdate(utils.NewContext(p.config, r, w))
			},
		)

		serverHandler.HandleFunc(
			"GET "+string(goidc.EndpointDynamicClient)+"/{client_id}",
			func(w http.ResponseWriter, r *http.Request) {
				api.HandleDynamicClientRetrieve(utils.NewContext(p.config, r, w))
			},
		)

		serverHandler.HandleFunc(
			"DELETE "+string(goidc.EndpointDynamicClient)+"/{client_id}",
			func(w http.ResponseWriter, r *http.Request) {
				api.HandleDynamicClientDelete(utils.NewContext(p.config, r, w))
			},
		)
	}

	if p.config.IntrospectionIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(goidc.EndpointTokenIntrospection),
			func(w http.ResponseWriter, r *http.Request) {
				api.HandleIntrospectionRequest(utils.NewContext(p.config, r, w))
			},
		)
	}

	return serverHandler
}

func (p *Provider) mtlsHandler() http.Handler {
	serverHandler := http.NewServeMux()

	serverHandler.HandleFunc(
		"POST "+string(goidc.EndpointToken),
		func(w http.ResponseWriter, r *http.Request) {
			api.HandleTokenRequest(utils.NewContext(p.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"GET "+string(goidc.EndpointUserInfo),
		func(w http.ResponseWriter, r *http.Request) {
			api.HandleUserInfoRequest(utils.NewContext(p.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"POST "+string(goidc.EndpointUserInfo),
		func(w http.ResponseWriter, r *http.Request) {
			api.HandleUserInfoRequest(utils.NewContext(p.config, r, w))
		},
	)

	if p.config.PARIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(goidc.EndpointPushedAuthorizationRequest),
			func(w http.ResponseWriter, r *http.Request) {
				api.HandleParRequest(utils.NewContext(p.config, r, w))
			},
		)
	}

	if p.config.IntrospectionIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(goidc.EndpointTokenIntrospection),
			func(w http.ResponseWriter, r *http.Request) {
				api.HandleIntrospectionRequest(utils.NewContext(p.config, r, w))
			},
		)
	}

	return serverHandler
}

// TODO: Add more validations.
func (p *Provider) validateConfiguration() error {

	return runValidations(
		*p,
		validateJWKS,
		validateSignatureKeys,
		validateEncryptionKeys,
		validatePrivateKeyJWTSignatureAlgorithms,
		validateClientSecretJWTSignatureAlgorithms,
		validateIntrospectionClientAuthnMethods,
		validateUserInfoEncryption,
		validateJAREncryption,
		validateJARMEncryption,
		validateTokenBinding,
		validateOpenIDDefaultIDTokenSignatureAlgorithm,
		validateOpenIDDefaultJARMSignatureAlgorithm,
		validateFAPI2ClientAuthnMethods,
		validateFAPI2ImplicitGrantIsNotAllowed,
		validateFAPI2PARIsRequired,
		validateFAPI2PkceIsRequired,
		validateFAPI2IssuerResponseParamIsRequired,
		validateFAPI2RefreshTokenRotation,
	)
}
