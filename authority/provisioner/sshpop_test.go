package provisioner

import (
	"crypto"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/jose"
	"golang.org/x/crypto/ssh"
)

func TestSSHPOP_Getters(t *testing.T) {
	p, err := generateSSHPOP()
	assert.FatalError(t, err)
	id := "sshpop/" + p.Name
	if got := p.GetID(); got != id {
		t.Errorf("SSHPOP.GetID() = %v, want %v", got, id)
	}
	if got := p.GetName(); got != p.Name {
		t.Errorf("SSHPOP.GetName() = %v, want %v", got, p.Name)
	}
	if got := p.GetType(); got != TypeSSHPOP {
		t.Errorf("SSHPOP.GetType() = %v, want %v", got, TypeSSHPOP)
	}
	kid, key, ok := p.GetEncryptedKey()
	if kid != "" || key != "" || ok == true {
		t.Errorf("SSHPOP.GetEncryptedKey() = (%v, %v, %v), want (%v, %v, %v)",
			kid, key, ok, "", "", false)
	}
}

func createSSHCert(cert *ssh.Certificate, signer ssh.Signer) (*ssh.Certificate, *jose.JSONWebKey, error) {
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	if err != nil {
		return nil, nil, err
	}
	cert.Key, err = ssh.NewPublicKey(jwk.Public().Key)
	if err != nil {
		return nil, nil, err
	}
	if err = cert.SignCert(rand.Reader, signer); err != nil {
		return nil, nil, err
	}
	return cert, jwk, nil
}

func generateSSHPOPToken(p Interface, cert *ssh.Certificate, jwk *jose.JSONWebKey) (string, error) {
	return generateToken("foo", p.GetName(), testAudiences.Sign[0], "",
		[]string{"test.smallstep.com"}, time.Now(), jwk, withSSHPOPFile(cert))
}

func TestSSHPOP_authorizeToken(t *testing.T) {
	key, err := pemutil.Read("./testdata/secrets/ssh_user_ca_key")
	assert.FatalError(t, err)
	signer, ok := key.(crypto.Signer)
	assert.Fatal(t, ok, "could not cast ssh signing key to crypto signer")
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	assert.FatalError(t, err)

	type test struct {
		p     *SSHPOP
		token string
		err   error
		code  int
	}
	tests := map[string]func(*testing.T) test{
		"fail/bad-token": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				code:  http.StatusBadRequest,
				err:   errors.New("authorizeToken: error extracting sshpop header from token: error parsing token: "),
			}
		},
		"fail/error-revoked-db-check": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			p.db = &db.MockAuthDB{
				MIsSSHRevoked: func(sn string) (bool, error) {
					return false, errors.New("fatal")
				},
			}
			cert, jwk, err := createSSHCert(&ssh.Certificate{CertType: ssh.UserCert}, sshSigner)
			assert.FatalError(t, err)
			tok, err := generateSSHPOPToken(p, cert, jwk)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusInternalServerError,
				err:   errors.New("authorizeToken: error checking checking sshpop cert revocation: fatal"),
			}
		},
		"fail/cert-already-revoked": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			p.db = &db.MockAuthDB{
				MIsSSHRevoked: func(sn string) (bool, error) {
					return true, nil
				},
			}
			cert, jwk, err := createSSHCert(&ssh.Certificate{CertType: ssh.UserCert}, sshSigner)
			assert.FatalError(t, err)
			tok, err := generateSSHPOPToken(p, cert, jwk)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusBadRequest,
				err:   errors.New("authorizeToken: sshpop certificate is revoked"),
			}
		},
		"fail/cert-not-yet-valid": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			p.db = &db.MockAuthDB{
				MIsSSHRevoked: func(sn string) (bool, error) {
					return false, nil
				},
			}
			cert, jwk, err := createSSHCert(&ssh.Certificate{
				CertType:   ssh.UserCert,
				ValidAfter: uint64(time.Now().Add(time.Minute).Unix()),
			}, sshSigner)
			assert.FatalError(t, err)
			tok, err := generateSSHPOPToken(p, cert, jwk)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("authorizeToken: sshpop certificate validAfter is in the future"),
			}
		},
		"fail/cert-past-validity": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			p.db = &db.MockAuthDB{
				MIsSSHRevoked: func(sn string) (bool, error) {
					return false, nil
				},
			}
			cert, jwk, err := createSSHCert(&ssh.Certificate{
				CertType:    ssh.UserCert,
				ValidBefore: uint64(time.Now().Add(-time.Minute).Unix()),
			}, sshSigner)
			assert.FatalError(t, err)
			tok, err := generateSSHPOPToken(p, cert, jwk)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("authorizeToken: sshpop certificate validBefore is in the past"),
			}
		},
		"fail/no-signer-found": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			p.db = &db.MockAuthDB{
				MIsSSHRevoked: func(sn string) (bool, error) {
					return false, nil
				},
			}
			cert, jwk, err := createSSHCert(&ssh.Certificate{CertType: ssh.HostCert}, sshSigner)
			assert.FatalError(t, err)
			tok, err := generateSSHPOPToken(p, cert, jwk)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusUnauthorized,
				err:   errors.New("authorizeToken: could not find valid ca signer to verify sshpop certificate"),
			}
		},
		"fail/error-parsing-claims-bad-sig": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			p.db = &db.MockAuthDB{
				MIsSSHRevoked: func(sn string) (bool, error) {
					return false, nil
				},
			}
			cert, _, err := createSSHCert(&ssh.Certificate{CertType: ssh.UserCert}, sshSigner)
			assert.FatalError(t, err)
			otherJWK, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			tok, err := generateSSHPOPToken(p, cert, otherJWK)
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusBadRequest,
				err:   errors.New("authorizeToken: error parsing sshpop token claims"),
			}
		},
		"fail/invalid-claims-issuer": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			p.db = &db.MockAuthDB{
				MIsSSHRevoked: func(sn string) (bool, error) {
					return false, nil
				},
			}
			cert, jwk, err := createSSHCert(&ssh.Certificate{CertType: ssh.UserCert}, sshSigner)
			assert.FatalError(t, err)
			tok, err := generateToken("foo", "bar", testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk, withSSHPOPFile(cert))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusBadRequest,
				err:   errors.New("authorizeToken: invalid sshpop token"),
			}
		},
		"fail/invalid-audience": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			p.db = &db.MockAuthDB{
				MIsSSHRevoked: func(sn string) (bool, error) {
					return false, nil
				},
			}
			cert, jwk, err := createSSHCert(&ssh.Certificate{CertType: ssh.UserCert}, sshSigner)
			assert.FatalError(t, err)
			tok, err := generateToken("foo", p.GetName(), "invalid-aud", "",
				[]string{"test.smallstep.com"}, time.Now(), jwk, withSSHPOPFile(cert))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusBadRequest,
				err:   errors.New("authorizeToken: sshpop token has invalid audience claim (aud)"),
			}
		},
		"fail/empty-subject": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			p.db = &db.MockAuthDB{
				MIsSSHRevoked: func(sn string) (bool, error) {
					return false, nil
				},
			}
			cert, jwk, err := createSSHCert(&ssh.Certificate{CertType: ssh.UserCert}, sshSigner)
			assert.FatalError(t, err)
			tok, err := generateToken("", p.GetName(), testAudiences.Sign[0], "",
				[]string{"test.smallstep.com"}, time.Now(), jwk, withSSHPOPFile(cert))
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: tok,
				code:  http.StatusBadRequest,
				err:   errors.New("authorizeToken: sshpop token subject cannot be empty"),
			}
		},
		"ok": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			p.db = &db.MockAuthDB{
				MIsSSHRevoked: func(sn string) (bool, error) {
					return false, nil
				},
			}
			cert, jwk, err := createSSHCert(&ssh.Certificate{CertType: ssh.UserCert}, sshSigner)
			assert.FatalError(t, err)
			tok, err := generateSSHPOPToken(p, cert, jwk)
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
				sc, ok := err.(errs.StatusCoder)
				assert.Fatal(t, ok, "error does not implement StatusCoder interface")
				assert.Equals(t, sc.StatusCode(), tc.code)
				if assert.NotNil(t, tc.err) {
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

/*
func TestSSHPOP_AuthorizeSign(t *testing.T) {
	type test struct {
		p     *SSHPOP
		token string
		ctx   context.Context
		err   error
	}
	tests := map[string]func(*testing.T) test{
		"fail/invalid-token": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				err:   errors.New("error parsing token"),
			}
		},
		"fail/ssh-unimplemented": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			tok, err := generateSSHPOPToken(jwk, nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				ctx:   NewContextWithMethod(context.Background(), SignSSHMethod),
				token: tok,
				err:   errors.Errorf("ssh certificates not enabled for k8s ServiceAccount provisioners"),
			}
		},
		"ok": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			tok, err := generateSSHPOPToken(jwk, nil)
			assert.FatalError(t, err)
			return test{
				p:     p,
				ctx:   NewContextWithMethod(context.Background(), SignMethod),
				token: tok,
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			if opts, err := tc.p.AuthorizeSign(tc.ctx, tc.token); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					if assert.NotNil(t, opts) {
						tot := 0
						for _, o := range opts {
							switch v := o.(type) {
							case *provisionerExtensionOption:
								assert.Equals(t, v.Type, int(TypeSSHPOP))
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

func TestSSHPOP_AuthorizeRevoke(t *testing.T) {
	type test struct {
		p     *SSHPOP
		token string
		err   error
	}
	tests := map[string]func(*testing.T) test{
		"fail/invalid-token": func(t *testing.T) test {
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			return test{
				p:     p,
				token: "foo",
				err:   errors.New("error parsing token"),
			}
		},
		"ok": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			p, err := generateSSHPOP()
			assert.FatalError(t, err)
			tok, err := generateSSHPOPToken(jwk, nil)
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
			if err := tc.p.AuthorizeRevoke(context.TODO(), tc.token); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestSSHPOP_AuthorizeRenew(t *testing.T) {
	p1, err := generateSSHPOP()
	assert.FatalError(t, err)
	p2, err := generateSSHPOP()
	assert.FatalError(t, err)

	// disable renewal
	disable := true
	p2.Claims = &Claims{DisableRenewal: &disable}
	p2.claimer, err = NewClaimer(p2.Claims, globalProvisionerClaims)
	assert.FatalError(t, err)

	type args struct {
		cert *x509.Certificate
	}
	tests := []struct {
		name    string
		prov    *SSHPOP
		args    args
		wantErr bool
	}{
		{"ok", p1, args{nil}, false},
		{"fail", p2, args{nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.prov.AuthorizeRenew(context.TODO(), tt.args.cert); (err != nil) != tt.wantErr {
				t.Errorf("X5C.AuthorizeRenew() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
*/
