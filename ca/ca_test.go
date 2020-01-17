package ca

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/crypto/x509util"
	stepJOSE "github.com/smallstep/cli/jose"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type ClosingBuffer struct {
	*bytes.Buffer
}

func (cb *ClosingBuffer) Close() error {
	return nil
}

func getCSR(priv interface{}) (*x509.CertificateRequest, error) {
	_csr := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "test.smallstep.com"},
		DNSNames: []string{"test.smallstep.com"},
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, _csr, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(csrBytes)
}

func TestMain(m *testing.M) {
	DisableIdentity = true
	os.Exit(m.Run())
}

func TestCASign(t *testing.T) {
	pub, priv, err := keys.GenerateDefaultKeyPair()
	assert.FatalError(t, err)

	asn1dn := &x509util.ASN1DN{
		Country:       "Tazmania",
		Organization:  "Acme Co",
		Locality:      "Landscapes",
		Province:      "Sudden Cliffs",
		StreetAddress: "TNT",
		CommonName:    "test.smallstep.com",
	}

	config, err := authority.LoadConfiguration("testdata/ca.json")
	assert.FatalError(t, err)
	config.AuthorityConfig.Template = asn1dn
	ca, err := New(config)
	assert.FatalError(t, err)

	intermediateIdentity, err := x509util.LoadIdentityFromDisk("testdata/secrets/intermediate_ca.crt",
		"testdata/secrets/intermediate_ca_key", pemutil.WithPassword([]byte("password")))
	assert.FatalError(t, err)

	clijwk, err := stepJOSE.ParseKey("testdata/secrets/step_cli_key_priv.jwk",
		stepJOSE.WithPassword([]byte("pass")))
	assert.FatalError(t, err)
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: clijwk.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", clijwk.KeyID))
	assert.FatalError(t, err)
	validAud := []string{"https://127.0.0.1:0/sign"}

	now := time.Now().UTC()
	leafExpiry := now.Add(time.Minute * 5)

	type signTest struct {
		ca     *CA
		body   string
		status int
		errMsg string
	}
	tests := map[string]func(t *testing.T) *signTest{
		"fail invalid-json-body": func(t *testing.T) *signTest {
			return &signTest{
				ca:     ca,
				body:   "invalid json",
				status: http.StatusBadRequest,
				errMsg: errs.BadRequestDefaultMsg,
			}
		},
		"fail invalid-csr-sig": func(t *testing.T) *signTest {
			der := []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIDNjCCAh4CAQAwYzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQH
DA1TYW4gRnJhbmNpc2NvMRIwEAYDVQQKDAlzbWFsbHN0ZXAxGzAZBgNVBAMMEnRl
c3Quc21hbGxzdGVwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ANPahliigZ38QpBLmQMS3MVKKZ5gapNjqR7LIEYoYWa4lTFiUnbwg8tSfIFcgLZr
jNIxn7/98+JOJHKgS03NhFJoS5hej0LyypleOGJ0nk2qawYVKnn1ftoKjkfxkfZI
a/5rsDF1jhNBspB/KPHWE0eimKQJbUiVG1zA1sExnXDecF3vJfBj+DPDWngx4yxR
/jYEKjt4tQ6Ei752TbosrCHYeYXzkr6iAwiNz6vT/ewLb6b8JmuN8X6Y1I9ogDGx
hntBJ1jAK8x3IGTjYbkm+mqVuCyhNcHtGfEHcBnUEzLAPrVFn8kGiAnU17FJ0uQ7
1C9CtUzgBRZCxSBm6Qs+Zs8CAwEAAaCBjTCBigYJKoZIhvcNAQkOMX0wezAMBgNV
HRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAOBgNVHQ8B
Af8EBAMCBaAwHQYDVR0RBBYwFIISdGVzdC5zbWFsbHN0ZXAuY29tMB0GA1UdDgQW
BBQj6N4RTAAjhV3UBYXH72mkdOGpqzANBgkqhkiG9w0BAQsFAAOCAQEAN0/ivCBk
FD53SqtRmqqc7C9saoRNvV+wDi4Sg6YGLFQLjbZPJrqQURWdHtV9O3sb3p8O5erX
9Kgq3C7fqd//0mro4GZ1GTpjsPKIMocZFfH7zEhAZlvQLRKWICjoBaOwxQum2qY/
B3+ltAXb4uqGdbI0jPkkyWGN5CQhK+ZHoYe/zGtTEmHBcPxRtJJkukQQjUgZhjU2
Z7K+w3AjOxj47XLNHHlW83QYUJ2mN+mEZF9DhrZb2ydYOlpy0V2NJwv7QrmnFaDj
R0v3BFLTblIp100li3oV2QaM/yESrgo9XIjEEGzCGz5cNs5ovNadufUZDCJyyT4q
ZEp7knvU2psWRw==
-----END CERTIFICATE REQUEST-----`)
			block, _ := pem.Decode(der)
			assert.NotNil(t, block)
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			assert.FatalError(t, err)

			body, err := json.Marshal(&api.SignRequest{
				CsrPEM: api.CertificateRequest{CertificateRequest: csr},
				OTT:    "foo",
			})
			assert.FatalError(t, err)
			return &signTest{
				ca:     ca,
				body:   string(body),
				status: http.StatusBadRequest,
				errMsg: errs.BadRequestDefaultMsg,
			}
		},
		"fail unauthorized-ott": func(t *testing.T) *signTest {
			csr, err := getCSR(priv)
			assert.FatalError(t, err)
			body, err := json.Marshal(&api.SignRequest{
				CsrPEM: api.CertificateRequest{CertificateRequest: csr},
				OTT:    "foo",
			})
			assert.FatalError(t, err)
			return &signTest{
				ca:     ca,
				body:   string(body),
				status: http.StatusUnauthorized,
				errMsg: errs.UnauthorizedDefaultMsg,
			}
		},
		"fail commonname-claim": func(t *testing.T) *signTest {
			jti, err := randutil.ASCII(32)
			assert.FatalError(t, err)
			cl := struct {
				jwt.Claims
				SANS []string `json:"sans"`
			}{
				Claims: jwt.Claims{
					Subject:   "invalid",
					Issuer:    "step-cli",
					NotBefore: jwt.NewNumericDate(now),
					Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
					Audience:  validAud,
					ID:        jti,
				},
				SANS: []string{"invalid"},
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			csr, err := getCSR(priv)
			assert.FatalError(t, err)
			body, err := json.Marshal(&api.SignRequest{
				CsrPEM: api.CertificateRequest{CertificateRequest: csr},
				OTT:    raw,
			})
			assert.FatalError(t, err)
			return &signTest{
				ca:     ca,
				body:   string(body),
				status: http.StatusUnauthorized,
				errMsg: errs.UnauthorizedDefaultMsg,
			}
		},
		"ok": func(t *testing.T) *signTest {
			jti, err := randutil.ASCII(32)
			assert.FatalError(t, err)
			cl := struct {
				jwt.Claims
				SANS []string `json:"sans"`
			}{
				Claims: jwt.Claims{
					Subject:   "test.smallstep.com",
					Issuer:    "step-cli",
					NotBefore: jwt.NewNumericDate(now),
					Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
					Audience:  validAud,
					ID:        jti,
				},
				SANS: []string{"test.smallstep.com"},
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			csr, err := getCSR(priv)
			assert.FatalError(t, err)
			body, err := json.Marshal(&api.SignRequest{
				CsrPEM:    api.CertificateRequest{CertificateRequest: csr},
				OTT:       raw,
				NotBefore: api.NewTimeDuration(now),
				NotAfter:  api.NewTimeDuration(leafExpiry),
			})
			assert.FatalError(t, err)
			return &signTest{
				ca:     ca,
				body:   string(body),
				status: http.StatusCreated,
			}
		},
		"ok-backwards-compat-missing-subject-SAN": func(t *testing.T) *signTest {
			jti, err := randutil.ASCII(32)
			assert.FatalError(t, err)
			cl := struct {
				jwt.Claims
				SANS []string `json:"sans"`
			}{
				Claims: jwt.Claims{
					Subject:   "test.smallstep.com",
					Issuer:    "step-cli",
					NotBefore: jwt.NewNumericDate(now),
					Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
					Audience:  validAud,
					ID:        jti,
				},
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			csr, err := getCSR(priv)
			assert.FatalError(t, err)
			body, err := json.Marshal(&api.SignRequest{
				CsrPEM:    api.CertificateRequest{CertificateRequest: csr},
				OTT:       raw,
				NotBefore: api.NewTimeDuration(now),
				NotAfter:  api.NewTimeDuration(leafExpiry),
			})
			assert.FatalError(t, err)
			return &signTest{
				ca:     ca,
				body:   string(body),
				status: http.StatusCreated,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			rq, err := http.NewRequest("POST", "/sign", strings.NewReader(tc.body))
			assert.FatalError(t, err)
			rr := httptest.NewRecorder()

			tc.ca.srv.Handler.ServeHTTP(rr, rq)

			if assert.Equals(t, rr.Code, tc.status) {
				body := &ClosingBuffer{rr.Body}
				if rr.Code < http.StatusBadRequest {
					var sign api.SignResponse
					assert.FatalError(t, readJSON(body, &sign))
					leaf := sign.ServerPEM.Certificate
					intermediate := sign.CaPEM.Certificate

					assert.Equals(t, leaf.NotBefore, now.Truncate(time.Second))
					assert.Equals(t, leaf.NotAfter, leafExpiry.Truncate(time.Second))

					assert.Equals(t, fmt.Sprintf("%v", leaf.Subject),
						fmt.Sprintf("%v", &pkix.Name{
							Country:       []string{asn1dn.Country},
							Organization:  []string{asn1dn.Organization},
							Locality:      []string{asn1dn.Locality},
							StreetAddress: []string{asn1dn.StreetAddress},
							Province:      []string{asn1dn.Province},
							CommonName:    asn1dn.CommonName,
						}))
					assert.Equals(t, leaf.Issuer, intermediate.Subject)

					assert.Equals(t, leaf.SignatureAlgorithm, x509.ECDSAWithSHA256)
					assert.Equals(t, leaf.PublicKeyAlgorithm, x509.ECDSA)
					assert.Equals(t, leaf.ExtKeyUsage,
						[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
					assert.Equals(t, leaf.DNSNames, []string{"test.smallstep.com"})

					pubBytes, err := x509.MarshalPKIXPublicKey(pub)
					assert.FatalError(t, err)
					hash := sha1.Sum(pubBytes)
					assert.Equals(t, leaf.SubjectKeyId, hash[:])

					assert.Equals(t, leaf.AuthorityKeyId, intermediateIdentity.Crt.SubjectKeyId)

					realIntermediate, err := x509.ParseCertificate(intermediateIdentity.Crt.Raw)
					assert.FatalError(t, err)
					assert.Equals(t, intermediate, realIntermediate)
				} else {
					err := readError(body)
					if len(tc.errMsg) == 0 {
						assert.FatalError(t, errors.New("must validate response error"))
					}
					assert.HasPrefix(t, err.Error(), tc.errMsg)
				}
			}
		})
	}
}

func TestCAProvisioners(t *testing.T) {
	config, err := authority.LoadConfiguration("testdata/ca.json")
	assert.FatalError(t, err)
	ca, err := New(config)
	assert.FatalError(t, err)

	type ekt struct {
		ca     *CA
		status int
		errMsg string
	}
	tests := map[string]func(t *testing.T) *ekt{
		"ok": func(t *testing.T) *ekt {
			return &ekt{
				ca:     ca,
				status: http.StatusOK,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			rq, err := http.NewRequest("GET", fmt.Sprintf("/provisioners"), strings.NewReader(""))
			assert.FatalError(t, err)
			rr := httptest.NewRecorder()

			tc.ca.srv.Handler.ServeHTTP(rr, rq)

			if assert.Equals(t, rr.Code, tc.status) {
				body := &ClosingBuffer{rr.Body}
				if rr.Code < http.StatusBadRequest {
					var resp api.ProvisionersResponse

					assert.FatalError(t, readJSON(body, &resp))
					a, err := json.Marshal(config.AuthorityConfig.Provisioners)
					assert.FatalError(t, err)
					b, err := json.Marshal(resp.Provisioners)
					assert.FatalError(t, err)
					assert.Equals(t, a, b)
				} else {
					err := readError(body)
					if len(tc.errMsg) == 0 {
						assert.FatalError(t, errors.New("must validate response error"))
					}
					assert.HasPrefix(t, err.Error(), tc.errMsg)
				}
			}
		})
	}
}

func TestCAProvisionerEncryptedKey(t *testing.T) {
	config, err := authority.LoadConfiguration("testdata/ca.json")
	assert.FatalError(t, err)
	ca, err := New(config)
	assert.FatalError(t, err)

	type ekt struct {
		ca          *CA
		kid         string
		expectedKey string
		status      int
		errMsg      string
	}
	tests := map[string]func(t *testing.T) *ekt{
		"not-found": func(t *testing.T) *ekt {
			return &ekt{
				ca:     ca,
				kid:    "foo",
				status: http.StatusNotFound,
				errMsg: errs.NotFoundDefaultMsg,
			}
		},
		"ok": func(t *testing.T) *ekt {
			p := config.AuthorityConfig.Provisioners[2].(*provisioner.JWK)
			return &ekt{
				ca:          ca,
				kid:         p.Key.KeyID,
				expectedKey: p.EncryptedKey,
				status:      http.StatusOK,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			rq, err := http.NewRequest("GET", fmt.Sprintf("/provisioners/%s/encrypted-key", tc.kid), strings.NewReader(""))
			assert.FatalError(t, err)
			rr := httptest.NewRecorder()

			tc.ca.srv.Handler.ServeHTTP(rr, rq)

			if assert.Equals(t, rr.Code, tc.status) {
				body := &ClosingBuffer{rr.Body}
				if rr.Code < http.StatusBadRequest {
					var ek api.ProvisionerKeyResponse
					assert.FatalError(t, readJSON(body, &ek))
					assert.Equals(t, ek.Key, tc.expectedKey)
				} else {
					err := readError(body)
					if len(tc.errMsg) == 0 {
						assert.FatalError(t, errors.New("must validate response error"))
					}
					assert.HasPrefix(t, err.Error(), tc.errMsg)
				}
			}
		})
	}
}

func TestCARoot(t *testing.T) {
	config, err := authority.LoadConfiguration("testdata/ca.json")
	assert.FatalError(t, err)
	ca, err := New(config)
	assert.FatalError(t, err)

	rootCrt, err := pemutil.ReadCertificate("testdata/secrets/root_ca.crt")
	assert.FatalError(t, err)

	type rootTest struct {
		ca     *CA
		sha    string
		status int
		errMsg string
	}
	tests := map[string]func(t *testing.T) *rootTest{
		"not-found": func(t *testing.T) *rootTest {
			return &rootTest{
				ca:     ca,
				sha:    "foo",
				status: http.StatusNotFound,
				errMsg: errs.NotFoundDefaultMsg,
			}
		},
		"success": func(t *testing.T) *rootTest {
			return &rootTest{
				ca:     ca,
				sha:    "ef742f95dc0d8aa82d3cca4017af6dac3fce84290344159891952d18c53eefe7",
				status: http.StatusOK,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			rq, err := http.NewRequest("GET", fmt.Sprintf("/root/%s", tc.sha), strings.NewReader(""))
			assert.FatalError(t, err)
			rr := httptest.NewRecorder()

			tc.ca.srv.Handler.ServeHTTP(rr, rq)

			if assert.Equals(t, rr.Code, tc.status) {
				body := &ClosingBuffer{rr.Body}
				if rr.Code < http.StatusBadRequest {
					var root api.RootResponse
					assert.FatalError(t, readJSON(body, &root))
					assert.Equals(t, root.RootPEM.Certificate, rootCrt)
				} else {
					err := readError(body)
					if len(tc.errMsg) == 0 {
						assert.FatalError(t, errors.New("must validate response error"))
					}
					assert.HasPrefix(t, err.Error(), tc.errMsg)
				}
			}
		})
	}
}

func TestCAHealth(t *testing.T) {
	config, err := authority.LoadConfiguration("testdata/ca.json")
	assert.FatalError(t, err)
	ca, err := New(config)
	assert.FatalError(t, err)

	type rootTest struct {
		ca     *CA
		status int
	}
	tests := map[string]func(t *testing.T) *rootTest{
		"success": func(t *testing.T) *rootTest {
			return &rootTest{
				ca:     ca,
				status: http.StatusOK,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			rq, err := http.NewRequest("GET", "/health", strings.NewReader(""))
			assert.FatalError(t, err)
			rr := httptest.NewRecorder()

			tc.ca.srv.Handler.ServeHTTP(rr, rq)

			if assert.Equals(t, rr.Code, tc.status) {
				body := &ClosingBuffer{rr.Body}
				if rr.Code < http.StatusBadRequest {
					var health api.HealthResponse
					assert.FatalError(t, readJSON(body, &health))
					assert.Equals(t, health, api.HealthResponse{Status: "ok"})
				}
			}
		})
	}
}

func TestCARenew(t *testing.T) {
	pub, _, err := keys.GenerateDefaultKeyPair()
	assert.FatalError(t, err)

	asn1dn := &x509util.ASN1DN{
		Country:       "Tazmania",
		Organization:  "Acme Co",
		Locality:      "Landscapes",
		Province:      "Sudden Cliffs",
		StreetAddress: "TNT",
		CommonName:    "test",
	}

	config, err := authority.LoadConfiguration("testdata/ca.json")
	assert.FatalError(t, err)
	config.AuthorityConfig.Template = asn1dn
	ca, err := New(config)
	assert.FatalError(t, err)
	assert.FatalError(t, err)

	intermediateIdentity, err := x509util.LoadIdentityFromDisk("testdata/secrets/intermediate_ca.crt",
		"testdata/secrets/intermediate_ca_key", pemutil.WithPassword([]byte("password")))
	assert.FatalError(t, err)

	now := time.Now().UTC()
	leafExpiry := now.Add(time.Minute * 5)

	type renewTest struct {
		ca           *CA
		tlsConnState *tls.ConnectionState
		status       int
		errMsg       string
	}
	tests := map[string]func(t *testing.T) *renewTest{
		"request-missing-tls": func(t *testing.T) *renewTest {
			return &renewTest{
				ca:           ca,
				tlsConnState: nil,
				status:       http.StatusBadRequest,
				errMsg:       errs.BadRequestDefaultMsg,
			}
		},
		"request-missing-peer-certificate": func(t *testing.T) *renewTest {
			return &renewTest{
				ca:           ca,
				tlsConnState: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{}},
				status:       http.StatusBadRequest,
				errMsg:       errs.BadRequestDefaultMsg,
			}
		},
		"success": func(t *testing.T) *renewTest {
			profile, err := x509util.NewLeafProfile("test", intermediateIdentity.Crt,
				intermediateIdentity.Key, x509util.WithPublicKey(pub),
				x509util.WithNotBeforeAfterDuration(now, leafExpiry, 0), x509util.WithHosts("funk"))
			assert.FatalError(t, err)
			crtBytes, err := profile.CreateCertificate()
			assert.FatalError(t, err)
			crt, err := x509.ParseCertificate(crtBytes)
			assert.FatalError(t, err)

			return &renewTest{
				ca: ca,
				tlsConnState: &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{crt},
				},
				status: http.StatusCreated,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			rq, err := http.NewRequest("POST", "/renew", strings.NewReader(""))
			assert.FatalError(t, err)
			rq.TLS = tc.tlsConnState
			rr := httptest.NewRecorder()

			tc.ca.srv.Handler.ServeHTTP(rr, rq)

			if assert.Equals(t, rr.Code, tc.status) {
				body := &ClosingBuffer{rr.Body}
				if rr.Code < http.StatusBadRequest {
					var sign api.SignResponse
					assert.FatalError(t, readJSON(body, &sign))
					leaf := sign.ServerPEM.Certificate
					intermediate := sign.CaPEM.Certificate

					assert.Equals(t, leaf.NotBefore, now.Truncate(time.Second))
					assert.Equals(t, leaf.NotAfter, leafExpiry.Truncate(time.Second))

					assert.Equals(t, fmt.Sprintf("%v", leaf.Subject),
						fmt.Sprintf("%v", &pkix.Name{
							CommonName: asn1dn.CommonName,
						}))
					assert.Equals(t, leaf.Issuer, intermediate.Subject)

					assert.Equals(t, leaf.SignatureAlgorithm, x509.ECDSAWithSHA256)
					assert.Equals(t, leaf.PublicKeyAlgorithm, x509.ECDSA)
					assert.Equals(t, leaf.ExtKeyUsage,
						[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
					assert.Equals(t, leaf.DNSNames, []string{"funk"})

					pubBytes, err := x509.MarshalPKIXPublicKey(pub)
					assert.FatalError(t, err)
					hash := sha1.Sum(pubBytes)
					assert.Equals(t, leaf.SubjectKeyId, hash[:])

					assert.Equals(t, leaf.AuthorityKeyId, intermediateIdentity.Crt.SubjectKeyId)

					realIntermediate, err := x509.ParseCertificate(intermediateIdentity.Crt.Raw)
					assert.FatalError(t, err)
					assert.Equals(t, intermediate, realIntermediate)

					assert.Equals(t, *sign.TLSOptions, authority.DefaultTLSOptions)
				} else {
					err := readError(body)
					if len(tc.errMsg) == 0 {
						assert.FatalError(t, errors.New("must validate response error"))
					}
					assert.HasPrefix(t, err.Error(), tc.errMsg)
				}
			}
		})
	}
}
