package goidc

import (
	"crypto/x509"
	"html/template"
	"log/slog"
	"time"
)

type TestContext struct {
	Scopes Scopes
}

func (testCtx TestContext) GetHost() string {
	return ""
}

func (testCtx TestContext) Header(header string) (headerValue string, ok bool) {
	return "", false
}

func (testCtx TestContext) FormParam(param string) (formValue string) {
	return ""
}

func (testCtx TestContext) SecureClientCertificate() (secureClientCert *x509.Certificate, ok bool) {
	return nil, false
}

func (testCtx TestContext) ClientCertificate() (clientCert *x509.Certificate, ok bool) {
	return nil, false
}

func (testCtx TestContext) RenderHTML(html string, params any) error {
	return nil
}

func (testCtx TestContext) RenderHTMLTemplate(tmpl *template.Template, params any) error {
	return nil
}

func (testCtx TestContext) Logger() *slog.Logger {
	return nil
}

func (testCtx TestContext) GetScopes() Scopes {
	return testCtx.Scopes
}

func (testCtx TestContext) Deadline() (deadline time.Time, ok bool) {
	return time.Now(), false
}

func (testCtx TestContext) Done() <-chan struct{} {
	return nil
}

func (testCtx TestContext) Err() error {
	return nil
}

func (testCtx TestContext) Value(key any) any {
	return nil
}

func GetTestContext(scopes Scopes) OAuthContext {
	return TestContext{
		Scopes: scopes,
	}
}