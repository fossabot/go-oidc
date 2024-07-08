# goidc
`goidc` is a client package that provides a customizable Authorization Server with support to OpenID Connect and other standards.

This library implements the following specifications:
* [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
* [JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)](https://openid.net/specs/oauth-v2-jarm.html)
* [`RFC 6749` - The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749.html)
* [`RFC 9126` - OAuth 2.0 Pushed Authorization Requests (PAR)](https://www.rfc-editor.org/rfc/rfc9126.html)
* [`RFC 9101` - The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR)](https://www.rfc-editor.org/rfc/rfc9101.html)
* [`RFC 7636` - Proof Key for Code Exchange by OAuth Public Clients (PKCE)](https://www.rfc-editor.org/rfc/rfc7636.html)
* [`RFC 9207` - OAuth 2.0 Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207.html)
* [`RFC 9449` - OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449.html)
* [`RFC 7662` OAuth 2.0 Token Introspection](https://www.rfc-editor.org/rfc/rfc7662.html)
## Get Started

To start using the `goidc` package in your project, install it with
```
go get github.com/luikymagno/goidc
```

Once installed, you can instantiate an openid provider and run it as shown below.
```go
// Create the server JWKS with just one key.
serverKeyID := "server_key"
var jwks goidc.JSONWebKeySet
if err := json.Unmarshal(
	[]byte("{\"keys\":[{\"p\":\"3-xp6XC0qLvqjLCCYTeY9Z4r6hAcySsGQDmp-T04vGompCGuAXYkU6iflqEE8J-vGZPghk0YQEdsWYx4H0GQPF_oz4N205N091LAiYUUYy-wIX0rPZ4qKiSdkAaXYNOHvpQMHs-ibi868IBEdvEpvUAHC5Z_zFNcxrTiVK_wuJc\",\"kty\":\"RSA\",\"q\":\"mjTPG0kaYyF2UXH5fvb7UQ4oUVocM-i7wyjJndJWVa9vGHSrpXi6aLR-llbfzokiRZPEOCZlCTmK-2oXXLzYEDZCLLigSXq-e3Z71l23c7wmypPaHNoq5XOXOSrEUN8-QLkA3vDthOx_HxNhektBSSeTGsnW_NhgcP5Csov3qQ0\",\"d\":\"FayeFDvs4ZjjfIMzGou324nh1wMPpkTV25CyYyzKsl-UWEotsE6TUWzDhFDspzJPsQ5Qtwdjms_zaSxnkfz4WTQMwP3QTk6i-6u6Ow73wkJzAZ4mWA-o798oA2EIobMfEg9_sd79DS2bJK5syMsjmJ0pXYrrZSCjaE8OdPNLH9w3ROoXdRqX5QepS0xHzofOYgMVNAOd5sXVmNCPbtgjkPOWSUs-O5WE-0Sqpbkm9mwt89aMRKb8jj1ZBd8t2s12AErBcwR9Pqn-vBwATN_SNxLuspPcZQtR4iKBDTJCDLvlfUVKOp5YSBoanZkldEgkD3sagBUbm242xlhKJ-vwGQ\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"server_key\",\"qi\":\"o9Mlti_fwa981ANQvEnwcrI-3FenGaNBXpn-CAK-YrKNgwP-fDGh9Ok2-c1os5o7H1ARzZisczxn4QrA7_712hwP1BgsO40kOOva36QywfeSgI1WbUJbfb2HEh7fOaZKBirCLc1sXo4kOBeCT4SQ3iSMATDX-y4P1SJkLm1HFlM\",\"dp\":\"Cfr2iYINe0vM23JujTi2J5RiLq-DKPAy-h_X1JUG91bf3AboQ4ZpfhUQ79zDZJopasFti27aOts0GBWrsPDyJc68iKs6W5nB59gXXsnAq98PQZ7bk4Z-KJyzLR0uGBG1higBFkp42eJfBSMiag67poS5C6osjgXVJ8IeKFojJ4c\",\"alg\":\"RS256\",\"dq\":\"NYXc2LCf6wZjRdOUcIATLMgIMGxhW5cNDKjsic3Gz4jLu6ZLKWzk7pCvW0kd91bbwWCPe5m_-dqyJZ9mKncVW1Mp1tHiOH7U_I9cXkQ69323zRpSWy9SMj_TnjD84MELn3VXGwputnNLkCKu876JE3Yb9fFWoH4Nw0pNJiG0vUU\",\"n\":\"huJo4_i7_uBNiB-wmZr7GIWKH0iUOJqDIir6PFDAgih3yt9zETFpVOn5dngo16VZLM1PTg8vMGOG97TBwPSCi2YGTA2MJTdJQEQ1jETQmkVov_kxR6OmPTZ5XUy-jZ6J9YMkYCKXD7IGIgW5VqkONwF7e8PVUHCc9o4U24F_MHyOv0P3dS9obMqxhr-5pbWHZ3K4ldQzXnpVnS-zV5nTSYa-Yh9lUYK9Qg2eejXPaXWdGFdF7lqtB_Pi6OdUwiDZhnVRBQdLarQHgx8qNU34AOUWvdL77eiqHWGd152_h7I9RObcvPRFbhh-wnx43go78tlgrJyYIMV2oCLs78YOqw\"}]}"),
	&jwks,
); err != nil {
	panic(err)
}
port := ":80"

// Instantiate the manager with all entities being saved in memory.
openidProvider := goidcp.NewProvider(
    "http://localhost" + port,
    goidcp.NewInMemoryClientManager(),
    goidcp.NewInMemoryAuthnSessionManager(),
    goidcp.NewInMemoryGrantSessionManager(),
    jwks,
    serverKeyID,
    serverKeyID,
)

openidProvider.Run(port)
```

You can check the default configurations by accessing http://localhost/.well-known/openid-configuration.

## Developers
To check test coverage, you can run:
```
make test-coverage
```

To see the documentation, you can install `pkgsite` with
```
go install golang.org/x/pkgsite/cmd/pkgsite@latest
```
And the run
```
make docs
```

Make sure the `GOBIN` environment variable is set.

## To Evaluate
* Add docs, docs should start with the name of the thing.
* Testify?
* How golang loads packages?
* Caching /authorize?
* Prefix scopes.
* Docker compose with mongo and CS.
* Add index to mongo db.
* Implement a bson decoder?
* Fix: given, when, then.
* Don't expose jose.
* Add more tests.
* Add coverage report and quality checks.
* Implement the revocation endpoint.
* Should I add the default encryption algorithm instead of requiring the dev to pass it?
* Implement the resource parameter.
* Implement a client credentials policy.
* Test the authorization details.
* Should I use "starts with" to validate scopes?
* Symmetric encryption for JAR?
* Support pairwise subject type.
* Add logs and log warnings.
* Create a package.
* Allow the dev to set an error template for /authorize.
* Client jwks is required for JAR.
* Handle expired sessions.
