package identity

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/cli/crypto/pemutil"
)

func TestLoadDefaultIdentity(t *testing.T) {
	oldFile := IdentityFile
	defer func() {
		IdentityFile = oldFile
	}()

	expected := &Identity{
		Type:        "mTLS",
		Certificate: "testdata/identity/identity.crt",
		Key:         "testdata/identity/identity_key",
	}
	tests := []struct {
		name    string
		prepare func()
		want    *Identity
		wantErr bool
	}{
		{"ok", func() { IdentityFile = "testdata/config/identity.json" }, expected, false},
		{"fail read", func() { IdentityFile = "testdata/config/missing.json" }, nil, true},
		{"fail unmarshal", func() { IdentityFile = "testdata/config/fail.json" }, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.prepare()
			got, err := LoadDefaultIdentity()
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadDefaultIdentity() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadDefaultIdentity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIdentity_Kind(t *testing.T) {
	type fields struct {
		Type string
	}
	tests := []struct {
		name   string
		fields fields
		want   Type
	}{
		{"disabled", fields{""}, Disabled},
		{"mutualTLS", fields{"mTLS"}, MutualTLS},
		{"unknown", fields{"unknown"}, Type("unknown")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &Identity{
				Type: tt.fields.Type,
			}
			if got := i.Kind(); got != tt.want {
				t.Errorf("Identity.Kind() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIdentity_Validate(t *testing.T) {
	type fields struct {
		Type        string
		Certificate string
		Key         string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"ok", fields{"mTLS", "testdata/identity/identity.crt", "testdata/identity/identity_key"}, false},
		{"ok disabled", fields{}, false},
		{"fail type", fields{"foo", "testdata/identity/identity.crt", "testdata/identity/identity_key"}, true},
		{"fail certificate", fields{"mTLS", "", "testdata/identity/identity_key"}, true},
		{"fail key", fields{"mTLS", "testdata/identity/identity.crt", ""}, true},
		{"fail missing certificate", fields{"mTLS", "testdata/identity/missing.crt", "testdata/identity/identity_key"}, true},
		{"fail missing key", fields{"mTLS", "testdata/identity/identity.crt", "testdata/identity/missing_key"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &Identity{
				Type:        tt.fields.Type,
				Certificate: tt.fields.Certificate,
				Key:         tt.fields.Key,
			}
			if err := i.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Identity.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIdentity_TLSCertificate(t *testing.T) {
	expected, err := tls.LoadX509KeyPair("testdata/identity/identity.crt", "testdata/identity/identity_key")
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		Type        string
		Certificate string
		Key         string
	}
	tests := []struct {
		name    string
		fields  fields
		want    tls.Certificate
		wantErr bool
	}{
		{"ok", fields{"mTLS", "testdata/identity/identity.crt", "testdata/identity/identity_key"}, expected, false},
		{"ok disabled", fields{}, tls.Certificate{}, false},
		{"fail type", fields{"foo", "testdata/identity/identity.crt", "testdata/identity/identity_key"}, tls.Certificate{}, true},
		{"fail certificate", fields{"mTLS", "testdata/certs/server.crt", "testdata/identity/identity_key"}, tls.Certificate{}, true},
		{"fail not after", fields{"mTLS", "testdata/identity/expired.crt", "testdata/identity/identity_key"}, tls.Certificate{}, true},
		{"fail not before", fields{"mTLS", "testdata/identity/not_before.crt", "testdata/identity/identity_key"}, tls.Certificate{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &Identity{
				Type:        tt.fields.Type,
				Certificate: tt.fields.Certificate,
				Key:         tt.fields.Key,
			}
			got, err := i.TLSCertificate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Identity.TLSCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Identity.TLSCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_fileExists(t *testing.T) {
	type args struct {
		filename string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok", args{"testdata/identity/identity.crt"}, false},
		{"missing", args{"testdata/identity/missing.crt"}, true},
		{"directory", args{"testdata/identity"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := fileExists(tt.args.filename); (err != nil) != tt.wantErr {
				t.Errorf("fileExists() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWriteDefaultIdentity(t *testing.T) {
	tmpDir, err := ioutil.TempDir(os.TempDir(), "go-tests")
	if err != nil {
		t.Fatal(err)
	}

	oldConfigDir := configDir
	oldIdentityDir := identityDir
	oldIdentityFile := IdentityFile
	defer func() {
		configDir = oldConfigDir
		identityDir = oldIdentityDir
		IdentityFile = oldIdentityFile
		os.RemoveAll(tmpDir)
	}()

	certs, err := pemutil.ReadCertificateBundle("testdata/identity/identity.crt")
	if err != nil {
		t.Fatal(err)
	}
	key, err := pemutil.Read("testdata/identity/identity_key")
	if err != nil {
		t.Fatal(err)
	}

	var certChain []api.Certificate
	for _, c := range certs {
		certChain = append(certChain, api.Certificate{Certificate: c})
	}

	configDir = filepath.Join(tmpDir, "config")
	identityDir = filepath.Join(tmpDir, "identity")
	IdentityFile = filepath.Join(tmpDir, "config", "identity.json")

	type args struct {
		certChain []api.Certificate
		key       crypto.PrivateKey
	}
	tests := []struct {
		name    string
		prepare func()
		args    args
		wantErr bool
	}{
		{"ok", func() {}, args{certChain, key}, false},
		{"fail mkdir config", func() {
			configDir = filepath.Join(tmpDir, "identity", "identity.crt")
			identityDir = filepath.Join(tmpDir, "identity")
		}, args{certChain, key}, true},
		{"fail mkdir identity", func() {
			configDir = filepath.Join(tmpDir, "config")
			identityDir = filepath.Join(tmpDir, "identity", "identity.crt")
		}, args{certChain, key}, true},
		{"fail certificate", func() {
			configDir = filepath.Join(tmpDir, "config")
			identityDir = filepath.Join(tmpDir, "bad-dir")
			os.MkdirAll(identityDir, 0600)
		}, args{certChain, key}, true},
		{"fail key", func() {
			configDir = filepath.Join(tmpDir, "config")
			identityDir = filepath.Join(tmpDir, "identity")
		}, args{certChain, "badKey"}, true},
		{"fail write identity", func() {
			configDir = filepath.Join(tmpDir, "bad-dir")
			identityDir = filepath.Join(tmpDir, "identity")
			IdentityFile = filepath.Join(configDir, "identity.json")
			os.MkdirAll(configDir, 0600)
		}, args{certChain, key}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.prepare()
			if err := WriteDefaultIdentity(tt.args.certChain, tt.args.key); (err != nil) != tt.wantErr {
				t.Errorf("WriteDefaultIdentity() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

type renewer struct {
	pool *x509.CertPool
	sign *api.SignResponse
	err  error
}

func (r *renewer) GetRootCAs() *x509.CertPool {
	return r.pool
}

func (r *renewer) Renew(tr http.RoundTripper) (*api.SignResponse, error) {
	return r.sign, r.err
}

func TestIdentity_Renew(t *testing.T) {
	tmpDir, err := ioutil.TempDir(os.TempDir(), "go-tests")
	if err != nil {
		t.Fatal(err)
	}

	oldIdentityDir := identityDir
	identityDir = "testdata/identity"
	defer func() {
		identityDir = oldIdentityDir
		os.RemoveAll(tmpDir)
	}()

	certs, err := pemutil.ReadCertificateBundle("testdata/identity/identity.crt")
	if err != nil {
		t.Fatal(err)
	}

	ok := &renewer{
		sign: &api.SignResponse{
			ServerPEM: api.Certificate{Certificate: certs[0]},
			CaPEM:     api.Certificate{Certificate: certs[1]},
			CertChainPEM: []api.Certificate{
				{Certificate: certs[0]},
				{Certificate: certs[1]},
			},
		},
	}

	okOld := &renewer{
		sign: &api.SignResponse{
			ServerPEM: api.Certificate{Certificate: certs[0]},
			CaPEM:     api.Certificate{Certificate: certs[1]},
		},
	}

	fail := &renewer{
		err: fmt.Errorf("an error"),
	}

	type fields struct {
		Type        string
		Certificate string
		Key         string
	}
	type args struct {
		client Renewer
	}
	tests := []struct {
		name    string
		prepare func()
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok", func() {}, fields{"mTLS", "testdata/identity/identity.crt", "testdata/identity/identity_key"}, args{ok}, false},
		{"ok old", func() {}, fields{"mTLS", "testdata/identity/identity.crt", "testdata/identity/identity_key"}, args{okOld}, false},
		{"ok disabled", func() {}, fields{}, args{nil}, false},
		{"fail type", func() {}, fields{"foo", "testdata/identity/identity.crt", "testdata/identity/identity_key"}, args{ok}, true},
		{"fail renew", func() {}, fields{"mTLS", "testdata/identity/identity.crt", "testdata/identity/identity_key"}, args{fail}, true},
		{"fail certificate", func() {}, fields{"mTLS", "testdata/certs/server.crt", "testdata/identity/identity_key"}, args{ok}, true},
		{"fail write identity", func() {
			identityDir = filepath.Join(tmpDir, "bad-dir")
			os.MkdirAll(identityDir, 0600)
		}, fields{"mTLS", "testdata/identity/identity.crt", "testdata/identity/identity_key"}, args{ok}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.prepare()
			i := &Identity{
				Type:        tt.fields.Type,
				Certificate: tt.fields.Certificate,
				Key:         tt.fields.Key,
			}
			if err := i.Renew(tt.args.client); (err != nil) != tt.wantErr {
				t.Errorf("Identity.Renew() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
