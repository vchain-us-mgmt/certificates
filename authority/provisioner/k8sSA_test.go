package provisioner

import (
	"context"
	"crypto/x509"
	"net/http"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/cli/jose"
)

func TestK8sSA_Getters(t *testing.T) {
	p, err := generateK8sSA(nil)
	assert.FatalError(t, err)
	id := "k8ssa/" + p.Name
	if got := p.GetID(); got != id {
		t.Errorf("K8sSA.GetID() = %v, want %v", got, id)
	}
	if got := p.GetName(); got != p.Name {
		t.Errorf("K8sSA.GetName() = %v, want %v", got, p.Name)
	}
	if got := p.GetType(); got != TypeK8sSA {
		t.Errorf("K8sSA.GetType() = %v, want %v", got, TypeK8sSA)
	}
	kid, key, ok := p.GetEncryptedKey()
	if kid != "" || key != "" || ok == true {
		t.Errorf("K8sSA.GetEncryptedKey() = (%v, %v, %v), want (%v, %v, %v)",
			kid, key, ok, "", "", false)
	}
}

func TestK8sSA_authorizeToken(t *testing.T) {
	type test struct {
		p     *K8sSA
		token string
		err   error
		code  int
	}
	tests := map[string]func(*testing.T) test{
		"fail/bad-token": func(t *testing.T) test {
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("k8ssa.authorizeToken; error parsing k8sSA token"),
			}
		},
		"fail/not-implemented": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			tok, err := generateToken("", p.Name, testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk)
			p.pubKeys = nil
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				err:   errors.New("k8ssa.authorizeToken; k8sSA TokenReview API integration not implemented"),
				code:  http.StatusUnauthorized,
			}
		},
		"fail/error-validating-token": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			tok, err := generateToken("", p.Name, testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				err:   errors.New("k8ssa.authorizeToken; error validating k8sSA token and extracting claims"),
				code:  http.StatusUnauthorized,
			}
		},
		"fail/invalid-issuer": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			p, err := generateK8sSA(jwk.Public().Key)
			assert.FatalError(t, err)
			claims := getK8sSAPayload()
			claims.Claims.Issuer = "invalid"
			tok, err := generateK8sSAToken(jwk, claims)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("k8ssa.authorizeToken; invalid k8sSA token claims: square/go-jose/jwt: validation failed, invalid issuer claim (iss)"),
			}
		},
		"ok": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			p, err := generateK8sSA(jwk.Public().Key)
			assert.FatalError(t, err)
			tok, err := generateK8sSAToken(jwk, nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			if claims, err := tc.p.authorizeToken(tc.token, testAudiences.Sign); err != nil {
				if assert.NotNil(t, tc.err) {
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.NotNil(t, claims)
				}
			}
		})
	}
}

func TestK8sSA_AuthorizeRevoke(t *testing.T) {
	type test struct {
		p     *K8sSA
		token string
		err   error
		code  int
	}
	tests := map[string]func(*testing.T) test{
		"fail/invalid-token": func(t *testing.T) test {
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("k8ssa.AuthorizeRevoke: k8ssa.authorizeToken; error parsing k8sSA token"),
			}
		},
		"ok": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			p, err := generateK8sSA(jwk.Public().Key)
			assert.FatalError(t, err)
			tok, err := generateK8sSAToken(jwk, nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			if err := tc.p.AuthorizeRevoke(context.Background(), tc.token); err != nil {
				sc, ok := err.(errs.StatusCoder)
				assert.Fatal(t, ok, "error does not implement StatusCoder interface")
				assert.Equals(t, sc.StatusCode(), tc.code)
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestK8sSA_AuthorizeRenew(t *testing.T) {
	type test struct {
		p    *K8sSA
		cert *x509.Certificate
		err  error
		code int
	}
	tests := map[string]func(*testing.T) test{
		"fail/renew-disabled": func(t *testing.T) test {
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			// disable renewal
			disable := true
			p.Claims = &Claims{DisableRenewal: &disable}
			p.claimer, err = NewClaimer(p.Claims, globalProvisionerClaims)
			assert.FatalError(t, err)
			return test{
				p:    p,
				cert: &x509.Certificate{},
				code: http.StatusUnauthorized,
				err:  errors.Errorf("k8ssa.AuthorizeRenew; renew is disabled for k8sSA provisioner %s", p.GetID()),
			}
		},
		"ok": func(t *testing.T) test {
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			return test{
				p:    p,
				cert: &x509.Certificate{},
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			if err := tc.p.AuthorizeRenew(context.Background(), tc.cert); err != nil {
				sc, ok := err.(errs.StatusCoder)
				assert.Fatal(t, ok, "error does not implement StatusCoder interface")
				assert.Equals(t, sc.StatusCode(), tc.code)
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestK8sSA_AuthorizeSign(t *testing.T) {
	type test struct {
		p     *K8sSA
		token string
		code  int
		err   error
	}
	tests := map[string]func(*testing.T) test{
		"fail/invalid-token": func(t *testing.T) test {
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("k8ssa.AuthorizeSign: k8ssa.authorizeToken; error parsing k8sSA token"),
			}
		},
		"ok": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			p, err := generateK8sSA(jwk.Public().Key)
			assert.FatalError(t, err)
			tok, err := generateK8sSAToken(jwk, nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			if opts, err := tc.p.AuthorizeSign(context.Background(), tc.token); err != nil {
				if assert.NotNil(t, tc.err) {
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					if assert.NotNil(t, opts) {
						tot := 0
						for _, o := range opts {
							switch v := o.(type) {
							case *provisionerExtensionOption:
								assert.Equals(t, v.Type, int(TypeK8sSA))
								assert.Equals(t, v.Name, tc.p.GetName())
								assert.Equals(t, v.CredentialID, "")
								assert.Len(t, 0, v.KeyValuePairs)
							case profileDefaultDuration:
								assert.Equals(t, time.Duration(v), tc.p.claimer.DefaultTLSCertDuration())
							case defaultPublicKeyValidator:
							case *validityValidator:
								assert.Equals(t, v.min, tc.p.claimer.MinTLSCertDuration())
								assert.Equals(t, v.max, tc.p.claimer.MaxTLSCertDuration())
							default:
								assert.FatalError(t, errors.Errorf("unexpected sign option of type %T", v))
							}
							tot++
						}
						assert.Equals(t, tot, 4)
					}
				}
			}
		})
	}
}

func TestK8sSA_AuthorizeSSHSign(t *testing.T) {
	type test struct {
		p     *K8sSA
		token string
		code  int
		err   error
	}
	tests := map[string]func(*testing.T) test{
		"fail/sshCA-disabled": func(t *testing.T) test {
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			// disable sshCA
			disable := false
			p.Claims = &Claims{EnableSSHCA: &disable}
			p.claimer, err = NewClaimer(p.Claims, globalProvisionerClaims)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.Errorf("k8ssa.AuthorizeSSHSign; sshCA is disabled for k8sSA provisioner %s", p.GetID()),
			}
		},
		"fail/invalid-token": func(t *testing.T) test {
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("k8ssa.AuthorizeSSHSign: k8ssa.authorizeToken; error parsing k8sSA token"),
			}
		},
		"ok": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			p, err := generateK8sSA(jwk.Public().Key)
			assert.FatalError(t, err)
			tok, err := generateK8sSAToken(jwk, nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			if opts, err := tc.p.AuthorizeSSHSign(context.Background(), tc.token); err != nil {
				if assert.NotNil(t, tc.err) {
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					if assert.NotNil(t, opts) {
						tot := 0
						for _, o := range opts {
							switch v := o.(type) {
							case sshCertDefaultsModifier:
								assert.Equals(t, v.CertType, SSHUserCert)
							case *sshDefaultExtensionModifier:
							case *sshCertificateValidityValidator:
								assert.Equals(t, v.Claimer, tc.p.claimer)
							case *sshDefaultPublicKeyValidator:
							case *sshCertificateDefaultValidator:
							case *sshDefaultDuration:
								assert.Equals(t, v.Claimer, tc.p.claimer)
							default:
								assert.FatalError(t, errors.Errorf("unexpected sign option of type %T", v))
							}
							tot++
						}
						assert.Equals(t, tot, 6)
					}
				}
			}
		})
	}
}

func TestK8sSA_AuthorizeSSHRevoke(t *testing.T) {
	type test struct {
		p     *K8sSA
		token string
		code  int
		err   error
	}
	tests := map[string]func(*testing.T) test{
		"not-implemented": func(t *testing.T) test {
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("provisioner.AuthorizeSSHRevoke not implemented"),
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			err := tc.p.AuthorizeSSHRevoke(context.Background(), tc.token)
			if assert.NotNil(t, err) {
				if assert.NotNil(t, tc.err) {
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			}
		})
	}
}

func TestK8sSA_AuthorizeSSHRekey(t *testing.T) {
	type test struct {
		p     *K8sSA
		token string
		code  int
		err   error
	}
	tests := map[string]func(*testing.T) test{
		"not-implemented": func(t *testing.T) test {
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("provisioner.AuthorizeSSHRekey not implemented"),
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			cert, opts, err := tc.p.AuthorizeSSHRekey(context.Background(), tc.token)
			if assert.NotNil(t, err) {
				if assert.NotNil(t, tc.err) {
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
					assert.Nil(t, cert)
					assert.Nil(t, opts)
				}
			}
		})
	}
}

func TestK8sSA_AuthorizeSSHRenew(t *testing.T) {
	type test struct {
		p     *K8sSA
		token string
		code  int
		err   error
	}
	tests := map[string]func(*testing.T) test{
		"not-implemented": func(t *testing.T) test {
			p, err := generateK8sSA(nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusUnauthorized,
				err:   errors.New("provisioner.AuthorizeSSHRenew not implemented"),
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			cert, err := tc.p.AuthorizeSSHRenew(context.Background(), tc.token)
			if assert.NotNil(t, err) {
				if assert.NotNil(t, tc.err) {
					sc, ok := err.(errs.StatusCoder)
					assert.Fatal(t, ok, "error does not implement StatusCoder interface")
					assert.Equals(t, sc.StatusCode(), tc.code)
					assert.HasPrefix(t, err.Error(), tc.err.Error())
					assert.Nil(t, cert)
				}
			}
		})
	}
}
