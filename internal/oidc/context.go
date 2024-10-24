package oidc

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type Context struct {
	Response http.ResponseWriter
	Request  *http.Request
	context  context.Context
	*Configuration
}

func NewContext(
	w http.ResponseWriter,
	r *http.Request,
	config *Configuration,
) Context {
	return Context{
		Configuration: config,
		Response:      w,
		Request:       r,
	}
}

func Handler(
	config *Configuration,
	exec func(ctx Context),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		exec(NewContext(w, r, config))
	}
}

func (ctx Context) TokenAuthnSigAlgs() []jose.SignatureAlgorithm {
	return ctx.clientAuthnSigAlgs(ctx.TokenAuthnMethods)
}

func (ctx Context) IsClientAllowedTokenIntrospection(c *goidc.Client) bool {
	if ctx.IsClientAllowedTokenIntrospectionFunc == nil {
		return false
	}

	return ctx.IsClientAllowedTokenIntrospectionFunc(c)
}

func (ctx Context) TokenIntrospectionAuthnSigAlgs() []jose.SignatureAlgorithm {
	return ctx.clientAuthnSigAlgs(ctx.TokenIntrospectionAuthnMethods)
}

func (ctx Context) IsClientAllowedTokenRevocation(c *goidc.Client) bool {
	if ctx.IsClientAllowedTokenRevocationFunc == nil {
		return false
	}

	return ctx.IsClientAllowedTokenRevocationFunc(c)
}

func (ctx Context) TokenRevocationAuthnSigAlgs() []jose.SignatureAlgorithm {
	return ctx.clientAuthnSigAlgs(ctx.TokenRevocationAuthnMethods)
}

func (ctx Context) ClientAuthnSigAlgs() []jose.SignatureAlgorithm {
	return append(ctx.PrivateKeyJWTSigAlgs, ctx.ClientSecretJWTSigAlgs...)
}

func (ctx Context) clientAuthnSigAlgs(methods []goidc.ClientAuthnType) []jose.SignatureAlgorithm {
	var sigAlgs []jose.SignatureAlgorithm

	if slices.Contains(methods, goidc.ClientAuthnPrivateKeyJWT) {
		sigAlgs = append(sigAlgs, ctx.PrivateKeyJWTSigAlgs...)
	}

	if slices.Contains(methods, goidc.ClientAuthnSecretJWT) {
		sigAlgs = append(sigAlgs, ctx.ClientSecretJWTSigAlgs...)
	}

	return sigAlgs
}

func (ctx Context) ClientCert() (*x509.Certificate, error) {

	if ctx.ClientCertFunc == nil {
		return nil, errors.New("the client certificate function was not defined")
	}

	return ctx.ClientCertFunc(ctx.Request)
}

func (ctx Context) ValidateInitalAccessToken(token string) error {
	if ctx.ValidateInitialAccessTokenFunc == nil {
		return nil
	}

	return ctx.ValidateInitialAccessTokenFunc(ctx.Request, token)
}

func (ctx Context) HandleDynamicClient(c *goidc.ClientMetaInfo) error {
	if ctx.HandleDynamicClientFunc == nil {
		return nil
	}

	return ctx.HandleDynamicClientFunc(ctx.Request, c)
}

func (ctx Context) CheckJTI(jti string) error {
	if ctx.CheckJTIFunc == nil {
		return nil
	}

	return ctx.CheckJTIFunc(ctx, jti)
}

func (ctx Context) RenderError(err error) error {
	if ctx.RenderErrorFunc == nil {
		// No need to call handleError here, since this error will end up being
		// passed to WriteError which already calls handleError.
		return err
	}

	ctx.NotifyError(err)
	return ctx.RenderErrorFunc(ctx.Response, ctx.Request, err)
}

func (ctx Context) NotifyError(err error) {
	if ctx.NotifyErrorFunc == nil {
		return
	}

	ctx.NotifyErrorFunc(ctx.Request, err)
}

// AssertionAudiences returns the host names trusted by the server to validate
// assertions.
func (ctx Context) AssertionAudiences() []string {
	audiences := []string{
		ctx.Host,
		ctx.BaseURL() + ctx.EndpointToken,
		ctx.Host + ctx.Request.RequestURI,
	}
	if ctx.MTLSIsEnabled {
		audiences = append(
			audiences,
			ctx.MTLSBaseURL()+ctx.EndpointToken,
			ctx.MTLSHost+ctx.Request.RequestURI,
		)
	}
	return audiences
}

func (ctx Context) Policy(id string) goidc.AuthnPolicy {
	for _, policy := range ctx.Policies {
		if policy.ID == id {
			return policy
		}
	}
	return goidc.AuthnPolicy{}
}

func (ctx Context) AvailablePolicy(
	client *goidc.Client,
	session *goidc.AuthnSession,
) (
	policy goidc.AuthnPolicy,
	ok bool,
) {
	for _, policy = range ctx.Policies {
		if ok = policy.SetUp(ctx.Request, client, session); ok {
			return policy, true
		}
	}

	return goidc.AuthnPolicy{}, false
}

func (ctx Context) CompareAuthDetails(
	granted []goidc.AuthorizationDetail,
	requested []goidc.AuthorizationDetail,
) error {
	if ctx.CompareAuthDetailsFunc == nil {
		return nil
	}
	return ctx.CompareAuthDetailsFunc(granted, requested)
}

//---------------------------------------- CRUD ----------------------------------------//

func (ctx Context) SaveClient(client *goidc.Client) error {
	if err := ctx.ClientManager.Save(ctx.Context(), client); err != nil {
		return goidc.Errorf(goidc.ErrorCodeInternalError, "internal error", err)
	}
	return nil
}

func (ctx Context) Client(id string) (*goidc.Client, error) {
	for _, staticClient := range ctx.StaticClients {
		if staticClient.ID == id {
			return staticClient, nil
		}
	}

	return ctx.ClientManager.Client(ctx.Context(), id)
}

func (ctx Context) DeleteClient(id string) error {
	return ctx.ClientManager.Delete(ctx.Context(), id)
}

func (ctx Context) SaveGrantSession(session *goidc.GrantSession) error {
	return ctx.GrantSessionManager.Save(
		ctx.Context(),
		session,
	)
}

func (ctx Context) GrantSessionByTokenID(
	id string,
) (
	*goidc.GrantSession,
	error,
) {
	return ctx.GrantSessionManager.SessionByTokenID(
		ctx.Context(),
		id,
	)
}

func (ctx Context) GrantSessionByRefreshToken(
	token string,
) (
	*goidc.GrantSession,
	error,
) {
	return ctx.GrantSessionManager.SessionByRefreshToken(
		ctx.Context(),
		token,
	)
}

func (ctx Context) DeleteGrantSession(id string) error {
	return ctx.GrantSessionManager.Delete(ctx.Context(), id)
}

func (ctx Context) DeleteGrantSessionByAuthorizationCode(code string) error {
	return ctx.GrantSessionManager.DeleteByAuthorizationCode(ctx.Context(), code)
}

func (ctx Context) SaveAuthnSession(session *goidc.AuthnSession) error {
	return ctx.AuthnSessionManager.Save(ctx.Context(), session)
}

func (ctx Context) AuthnSessionByCallbackID(
	id string,
) (
	*goidc.AuthnSession,
	error,
) {
	return ctx.AuthnSessionManager.SessionByCallbackID(ctx.Context(), id)
}

func (ctx Context) AuthnSessionByAuthorizationCode(
	code string,
) (
	*goidc.AuthnSession,
	error,
) {
	return ctx.AuthnSessionManager.SessionByAuthorizationCode(
		ctx.Context(),
		code,
	)
}

func (ctx Context) AuthnSessionByRequestURI(
	uri string,
) (
	*goidc.AuthnSession,
	error,
) {
	return ctx.AuthnSessionManager.SessionByReferenceID(ctx.Context(), uri)
}

func (ctx Context) DeleteAuthnSession(id string) error {
	return ctx.AuthnSessionManager.Delete(ctx.Context(), id)
}

//---------------------------------------- HTTP Utils ----------------------------------------//

func (ctx Context) BaseURL() string {
	return ctx.Host + ctx.EndpointPrefix
}

func (ctx Context) MTLSBaseURL() string {
	return ctx.MTLSHost + ctx.EndpointPrefix
}

func (ctx Context) BearerToken() (string, bool) {
	token, tokenType, ok := ctx.AuthorizationToken()
	if !ok {
		return "", false
	}

	if tokenType != goidc.TokenTypeBearer {
		return "", false
	}

	return token, true
}

func (ctx Context) AuthorizationToken() (
	token string,
	tokenType goidc.TokenType,
	ok bool,
) {
	tokenHeader, ok := ctx.Header("Authorization")
	if !ok {
		return "", "", false
	}

	tokenParts := strings.Split(tokenHeader, " ")
	if len(tokenParts) != 2 {
		return "", "", false
	}

	return tokenParts[1], goidc.TokenType(tokenParts[0]), true
}

func (ctx Context) Header(name string) (string, bool) {
	value := ctx.Request.Header.Get(name)
	if value == "" {
		return "", false
	}

	return value, true
}

func (ctx Context) RequestMethod() string {
	return ctx.Request.Method
}

func (ctx Context) FormParam(param string) string {

	if err := ctx.Request.ParseForm(); err != nil {
		return ""
	}

	return ctx.Request.PostFormValue(param)
}

func (ctx Context) FormData() map[string]any {

	if err := ctx.Request.ParseForm(); err != nil {
		return map[string]any{}
	}

	formData := make(map[string]any)
	for param, values := range ctx.Request.PostForm {
		formData[param] = values[0]
	}
	return formData
}

func (ctx Context) WriteStatus(status int) {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Context().Done():
		return
	default:
	}

	ctx.Response.WriteHeader(status)
}

// Write responds the current request writing obj as JSON.
func (ctx Context) Write(obj any, status int) error {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Context().Done():
		return nil
	default:
	}

	ctx.Response.Header().Set("Content-Type", "application/json")
	ctx.Response.WriteHeader(status)
	if err := json.NewEncoder(ctx.Response).Encode(obj); err != nil {
		return err
	}

	return nil
}

func (ctx Context) WriteJWT(token string, status int) error {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Context().Done():
		return nil
	default:
	}

	ctx.Response.Header().Set("Content-Type", "application/jwt")
	ctx.Response.WriteHeader(status)

	if _, err := ctx.Response.Write([]byte(token)); err != nil {
		return err
	}

	return nil
}

func (ctx Context) WriteError(err error) {

	ctx.NotifyError(err)

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		if err := ctx.Write(map[string]any{
			"error":             goidc.ErrorCodeInternalError,
			"error_description": "internal error",
		}, http.StatusInternalServerError); err != nil {
			ctx.Response.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	if err := ctx.Write(oidcErr, oidcErr.Code.StatusCode()); err != nil {
		ctx.Response.WriteHeader(http.StatusInternalServerError)
	}
}

func (ctx Context) Redirect(redirectURL string) {
	http.Redirect(ctx.Response, ctx.Request, redirectURL, http.StatusSeeOther)
}

func (ctx Context) RenderHTML(
	html string,
	params any,
) error {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Context().Done():
		return nil
	default:
	}

	ctx.Response.Header().Set("Content-Type", "text/html")
	ctx.Response.WriteHeader(http.StatusOK)
	tmpl, _ := template.New("default").Parse(html)
	return tmpl.Execute(ctx.Response, params)
}

//---------------------------------------- Key Management ----------------------------------------//

func (ctx Context) SigAlgs() []jose.SignatureAlgorithm {
	var algorithms []jose.SignatureAlgorithm
	for _, privateKey := range ctx.PrivateJWKS.Keys {
		if privateKey.Use == string(goidc.KeyUsageSignature) {
			algorithms = append(algorithms, jose.SignatureAlgorithm(privateKey.Algorithm))
		}
	}
	return algorithms
}

func (ctx Context) PublicKeys() jose.JSONWebKeySet {
	publicKeys := []jose.JSONWebKey{}
	for _, privateKey := range ctx.PrivateJWKS.Keys {
		publicKeys = append(publicKeys, privateKey.Public())
	}

	return jose.JSONWebKeySet{Keys: publicKeys}
}

func (ctx Context) PublicKey(keyID string) (jose.JSONWebKey, bool) {
	key, ok := ctx.PrivateKey(keyID)
	if !ok {
		return jose.JSONWebKey{}, false
	}

	return key.Public(), true
}

func (ctx Context) PrivateKey(keyID string) (jose.JSONWebKey, bool) {
	keys := ctx.PrivateJWKS.Key(keyID)
	if len(keys) == 0 {
		return jose.JSONWebKey{}, false
	}
	return keys[0], true
}

func (ctx Context) UserInfoSigKeyForClient(c *goidc.Client) (jose.JSONWebKey, bool) {
	if c.UserInfoSigAlg == "" {
		return ctx.UserSigKey()
	}

	return ctx.privateKeyByAlg(c.UserInfoSigAlg)
}

func (ctx Context) IDTokenSigKeyForClient(c *goidc.Client) (jose.JSONWebKey, bool) {
	if c.IDTokenSigAlg == "" {
		return ctx.UserSigKey()
	}

	return ctx.privateKeyByAlg(c.IDTokenSigAlg)
}

func (ctx Context) UserSigKey() (jose.JSONWebKey, bool) {
	return ctx.privateKeyByAlg(ctx.UserDefaultSigAlg)
}

func (ctx Context) UserInfoSigAlgsContainsNone() bool {
	return slices.Contains(ctx.UserSigAlgs, goidc.NoneSignatureAlgorithm)
}

func (ctx Context) JARMSigKeyForClient(c *goidc.Client) (jose.JSONWebKey, bool) {
	if c.JARMSigAlg == "" {
		return ctx.privateKeyByAlg(ctx.JARMDefaultSigAlg)
	}

	return ctx.privateKeyByAlg(c.JARMSigAlg)
}

// func (ctx Context) keyEncAlgs(keyIDs []string) []jose.KeyAlgorithm {
// 	var algorithms []jose.KeyAlgorithm
// 	for _, keyID := range keyIDs {
// 		key := ctx.privateKey(keyID)
// 		algorithms = append(algorithms, jose.KeyAlgorithm(key.Algorithm))
// 	}
// 	return algorithms
// }

// func (ctx Context) sigAlgs(keyIDs []string) []jose.SignatureAlgorithm {
// 	var algorithms []jose.SignatureAlgorithm
// 	for _, keyID := range keyIDs {
// 		key := ctx.privateKey(keyID)
// 		algorithms = append(algorithms, jose.SignatureAlgorithm(key.Algorithm))
// 	}
// 	return algorithms
// }

// privateKeyByAlg tries to find a key that matches the signature algorithm from
// the server JWKS.
func (ctx Context) privateKeyByAlg(
	alg jose.SignatureAlgorithm,
) (
	jose.JSONWebKey,
	bool,
) {
	for _, jwk := range ctx.PrivateJWKS.Keys {
		if jwk.Algorithm == string(alg) {
			return jwk, true
		}
	}

	return jose.JSONWebKey{}, false
}

// // privateKey returns a private JWK based on the key ID.
// // This is intended to be used with key IDs we're sure are present in the server JWKS.
// func (ctx Context) privateKey(keyID string) jose.JSONWebKey {
// 	keys := ctx.PrivateJWKS.Key(keyID)
// 	return keys[0]
// }

func (ctx Context) ShouldIssueRefreshToken(
	client *goidc.Client,
	grantInfo goidc.GrantInfo,
) bool {
	if ctx.ShouldIssueRefreshTokenFunc == nil ||
		!slices.Contains(client.GrantTypes, goidc.GrantRefreshToken) {
		return false
	}

	return ctx.ShouldIssueRefreshTokenFunc(client, grantInfo)
}

func (ctx Context) TokenOptions(
	grantInfo goidc.GrantInfo,
) goidc.TokenOptions {

	opts := ctx.TokenOptionsFunc(grantInfo)

	// Opaque access tokens cannot be the same size of refresh tokens.
	if opts.OpaqueLength == goidc.RefreshTokenLength {
		opts.OpaqueLength++
	}

	return opts
}

func (ctx Context) HandleGrant(grantInfo *goidc.GrantInfo) error {
	if ctx.HandleGrantFunc == nil {
		return nil
	}

	err := ctx.HandleGrantFunc(ctx.Request, grantInfo)
	if err == nil {
		return nil
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		return goidc.Errorf(goidc.ErrorCodeAccessDenied, "access denied", err)
	}

	return oidcErr
}

func (ctx Context) HandleJWTBearerGrantAssertion(assertion string) (goidc.JWTBearerGrantInfo, error) {
	return ctx.HandleJWTBearerGrantAssertionFunc(ctx.Request, assertion)
}

func (ctx Context) HTTPClient() *http.Client {

	if ctx.HTTPClientFunc == nil {
		return http.DefaultClient
	}

	return ctx.HTTPClientFunc(ctx.Context())
}

//---------------------------------------- context.Context ----------------------------------------//

func (ctx Context) Context() context.Context {
	if ctx.context != nil {
		return ctx.context
	}
	return ctx.Request.Context()
}

func (ctx *Context) SetContext(c context.Context) {
	ctx.context = c
}

func (ctx Context) Deadline() (deadline time.Time, ok bool) {
	if ctx.context != nil {
		return ctx.context.Deadline()
	}
	return ctx.Context().Deadline()
}

func (ctx Context) Done() <-chan struct{} {
	if ctx.context != nil {
		return ctx.context.Done()
	}
	return ctx.Context().Done()
}

func (ctx Context) Err() error {
	if ctx.context != nil {
		return ctx.context.Err()
	}
	return ctx.Context().Err()
}

func (ctx Context) Value(key any) any {
	if ctx.context != nil {
		return ctx.context.Value(key)
	}
	return ctx.Context().Value(key)
}
