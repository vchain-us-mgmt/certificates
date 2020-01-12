package authority

import (
	"context"
	"crypto/x509"
	"net/http"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/jose"
	"gopkg.in/square/go-jose.v2/jwt"
)

func generateToken(sub, iss, aud string, sans []string, iat time.Time, jwk *jose.JSONWebKey) (string, error) {
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		new(jose.SignerOptions).WithType("JWT").WithHeader("kid", jwk.KeyID),
	)
	if err != nil {
		return "", err
	}

	id, err := randutil.ASCII(64)
	if err != nil {
		return "", err
	}

	claims := struct {
		jose.Claims
		SANS []string `json:"sans"`
	}{
		Claims: jose.Claims{
			ID:        id,
			Subject:   sub,
			Issuer:    iss,
			IssuedAt:  jose.NewNumericDate(iat),
			NotBefore: jose.NewNumericDate(iat),
			Expiry:    jose.NewNumericDate(iat.Add(5 * time.Minute)),
			Audience:  []string{aud},
		},
		SANS: sans,
	}
	return jose.Signed(sig).Claims(claims).CompactSerialize()
}

func TestAuthority_authorizeToken(t *testing.T) {
	a := testAuthority(t)

	jwk, err := jose.ParseKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	assert.FatalError(t, err)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
	assert.FatalError(t, err)

	now := time.Now().UTC()

	validIssuer := "step-cli"
	validAudience := []string{"https://test.ca.smallstep.com/revoke"}

	type authorizeTest struct {
		auth *Authority
		ott  string
		err  error
		code int
	}
	tests := map[string]func(t *testing.T) *authorizeTest{
		"fail/invalid-ott": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth: a,
				ott:  "foo",
				err:  errors.New("authorizeToken: error parsing token"),
				code: http.StatusUnauthorized,
			}
		},
		"fail/prehistoric-token": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				IssuedAt:  jwt.NewNumericDate(now.Add(-time.Hour)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
				err:  errors.New("authorizeToken: token issued before the bootstrap of certificate authority"),
				code: http.StatusUnauthorized,
			}
		},
		"fail/provisioner-not-found": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "44",
			}
			_sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
				(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "foo"))
			assert.FatalError(t, err)

			raw, err := jwt.Signed(_sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
				err:  errors.New("authorizeToken: provisioner not found or invalid audience (https://test.ca.smallstep.com/revoke)"),
				code: http.StatusUnauthorized,
			}
		},
		"ok/simpledb": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
			}
		},
		"fail/simpledb/token-already-used": func(t *testing.T) *authorizeTest {
			_a := testAuthority(t)
			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			_, err = _a.authorizeToken(context.TODO(), raw)
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: _a,
				ott:  raw,
				err:  errors.New("authorizeToken: token already used"),
				code: http.StatusUnauthorized,
			}
		},
		"ok/mockNoSQLDB": func(t *testing.T) *authorizeTest {
			_a := testAuthority(t)
			_a.db = &db.MockAuthDB{
				MUseToken: func(id, tok string) (bool, error) {
					return true, nil
				},
			}

			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: _a,
				ott:  raw,
			}
		},
		"fail/mockNoSQLDB/error": func(t *testing.T) *authorizeTest {
			_a := testAuthority(t)
			_a.db = &db.MockAuthDB{
				MUseToken: func(id, tok string) (bool, error) {
					return false, errors.New("force")
				},
			}

			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: _a,
				ott:  raw,
				err:  errors.New("authorizeToken: failed when attempting to store token: force"),
				code: http.StatusInternalServerError,
			}
		},
		"fail/mockNoSQLDB/token-already-used": func(t *testing.T) *authorizeTest {
			_a := testAuthority(t)
			_a.db = &db.MockAuthDB{
				MUseToken: func(id, tok string) (bool, error) {
					return false, nil
				},
			}

			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: _a,
				ott:  raw,
				err:  errors.New("authorizeToken: token already used"),
				code: http.StatusUnauthorized,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			p, err := tc.auth.authorizeToken(context.TODO(), tc.ott)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())

					ctxErr, ok := err.(*errs.Error)
					assert.Fatal(t, ok, "error is not of type *errs.Error")
					assert.Equals(t, ctxErr.Details["ott"], tc.ott)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, p.GetID(), "step-cli:4UELJx8e0aS9m0CH3fZ0EB7D5aUPICb759zALHFejvc")
				}
			}
		})
	}
}

func TestAuthority_authorizeRevoke(t *testing.T) {
	a := testAuthority(t)

	jwk, err := jose.ParseKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	assert.FatalError(t, err)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
	assert.FatalError(t, err)

	now := time.Now().UTC()

	validIssuer := "step-cli"
	validAudience := []string{"https://test.ca.smallstep.com/revoke"}

	type authorizeTest struct {
		auth  *Authority
		token string
		err   error
		code  int
	}
	tests := map[string]func(t *testing.T) *authorizeTest{
		"fail/token/invalid-ott": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth:  a,
				token: "foo",
				err:   errors.New("authority.authorizeRevoke: authorizeToken: error parsing token"),
				code:  http.StatusUnauthorized,
			}
		},
		"fail/token/invalid-subject": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  a,
				token: raw,
				err:   errors.New("authority.authorizeRevoke: authorizeRevoke: authorizeToken: jwk token subject cannot be empty"),
				code:  http.StatusUnauthorized,
			}
		},
		"ok/token": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "44",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:  a,
				token: raw,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			if err := tc.auth.authorizeRevoke(context.TODO(), tc.token); err != nil {
				if assert.NotNil(t, tc.err) {
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())

					ctxErr, ok := err.(*errs.Error)
					assert.Fatal(t, ok, "error is not of type *errs.Error")
					assert.Equals(t, ctxErr.Details["ott"], tc.token)
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestAuthority_authorizeSign(t *testing.T) {
	a := testAuthority(t)

	jwk, err := jose.ParseKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	assert.FatalError(t, err)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
	assert.FatalError(t, err)

	now := time.Now().UTC()

	validIssuer := "step-cli"
	validAudience := []string{"https://test.ca.smallstep.com/sign"}

	type authorizeTest struct {
		auth *Authority
		ott  string
		err  error
		code int
	}
	tests := map[string]func(t *testing.T) *authorizeTest{
		"fail/invalid-ott": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth: a,
				ott:  "foo",
				err:  errors.New("authority.authorizeSign: authorizeToken: error parsing token"),
				code: http.StatusUnauthorized,
			}
		},
		"fail/invalid-subject": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
				err:  errors.New("authority.authorizeSign: authorizeSign: authorizeToken: jwk token subject cannot be empty"),
				code: http.StatusUnauthorized,
			}
		},
		"ok": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "44",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			got, err := tc.auth.AuthorizeSign(tc.ott)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())

					ctxErr, ok := err.(*errs.Error)
					assert.Fatal(t, ok, "error is not of type *errs.Error")
					assert.Equals(t, ctxErr.Details["ott"], tc.ott)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Len(t, 8, got)
				}
			}
		})
	}
}

func TestAuthority_Authorize(t *testing.T) {
	a := testAuthority(t)

	jwk, err := jose.ParseKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	assert.FatalError(t, err)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
	assert.FatalError(t, err)

	now := time.Now().UTC()

	validIssuer := "step-cli"
	validAudience := []string{"https://test.ca.smallstep.com/sign"}

	type authorizeTest struct {
		auth *Authority
		ott  string
		err  *apiError
	}
	tests := map[string]func(t *testing.T) *authorizeTest{
		"fail/invalid-ott": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth: a,
				ott:  "foo",
				err: &apiError{errors.New("authorizeSign: authorizeToken: error parsing token"),
					http.StatusUnauthorized, apiCtx{"ott": "foo"}},
			}
		},
		"fail/invalid-subject": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
				err: &apiError{errors.New("authorizeSign: token subject cannot be empty"),
					http.StatusUnauthorized, apiCtx{"ott": raw}},
			}
		},
		"ok": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "44",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)
			ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.SignMethod)
			got, err := tc.auth.Authorize(ctx, tc.ott)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assert.Nil(t, got)
					switch v := err.(type) {
					case *apiError:
						assert.HasPrefix(t, v.err.Error(), tc.err.Error())
						assert.Equals(t, v.code, tc.err.code)
						assert.Equals(t, v.context, tc.err.context)
					default:
						t.Errorf("unexpected error type: %T", v)
					}
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Len(t, 8, got)
				}
			}
		})
	}
}

func TestAuthority_authorizeRenew(t *testing.T) {
	fooCrt, err := pemutil.ReadCertificate("testdata/certs/foo.crt")
	assert.FatalError(t, err)

	renewDisabledCrt, err := pemutil.ReadCertificate("testdata/certs/renew-disabled.crt")
	assert.FatalError(t, err)

	otherCrt, err := pemutil.ReadCertificate("testdata/certs/provisioner-not-found.crt")
	assert.FatalError(t, err)

	type authorizeTest struct {
		auth *Authority
		cert *x509.Certificate
		err  error
		code int
	}
	tests := map[string]func(t *testing.T) *authorizeTest{
		"fail/db.IsRevoked-error": func(t *testing.T) *authorizeTest {
			a := testAuthority(t)
			a.db = &db.MockAuthDB{
				MIsRevoked: func(key string) (bool, error) {
					return false, errors.New("force")
				},
			}

			return &authorizeTest{
				auth: a,
				cert: fooCrt,
				err:  errors.New("authority.authorizeRenew: force"),
				code: http.StatusInternalServerError,
			}
		},
		"fail/revoked": func(t *testing.T) *authorizeTest {
			a := testAuthority(t)
			a.db = &db.MockAuthDB{
				MIsRevoked: func(key string) (bool, error) {
					return true, nil
				},
			}
			return &authorizeTest{
				auth: a,
				cert: fooCrt,
				err:  errors.New("authority.authorizeRenew: certificate has been revoked"),
				code: http.StatusUnauthorized,
			}
		},
		"fail/load-provisioner": func(t *testing.T) *authorizeTest {
			a := testAuthority(t)
			a.db = &db.MockAuthDB{
				MIsRevoked: func(key string) (bool, error) {
					return false, nil
				},
			}
			return &authorizeTest{
				auth: a,
				cert: otherCrt,
				err:  errors.New("authority.authorizeRenew: provisioner not found"),
				code: http.StatusUnauthorized,
			}
		},
		"fail/provisioner-authorize-renewal-fail": func(t *testing.T) *authorizeTest {
			a := testAuthority(t)
			a.db = &db.MockAuthDB{
				MIsRevoked: func(key string) (bool, error) {
					return false, nil
				},
			}

			return &authorizeTest{
				auth: a,
				cert: renewDisabledCrt,
				err:  errors.New("authority.authorizeRenew: authorizeRenew: renew is disabled for jwk provisioner renew_disabled:IMi94WBNI6gP5cNHXlZYNUzvMjGdHyBRmFoo-lCEaqk"),
				code: http.StatusUnauthorized,
			}
		},
		"ok": func(t *testing.T) *authorizeTest {
			a := testAuthority(t)
			a.db = &db.MockAuthDB{
				MIsRevoked: func(key string) (bool, error) {
					return false, nil
				},
			}
			return &authorizeTest{
				auth: a,
				cert: fooCrt,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			err := tc.auth.authorizeRenew(tc.cert)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())

					ctxErr, ok := err.(*errs.Error)
					assert.Fatal(t, ok, "error is not of type *errs.Error")
					assert.Equals(t, ctxErr.Details["serialNumber"], tc.cert.SerialNumber.String())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}
