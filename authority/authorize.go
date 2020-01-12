package authority

import (
	"context"
	"crypto/x509"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/cli/jose"
)

// Claims extends jose.Claims with step attributes.
type Claims struct {
	jose.Claims
	SANs  []string `json:"sans,omitempty"`
	Email string   `json:"email,omitempty"`
	Nonce string   `json:"nonce,omitempty"`
}

type skipTokenReuseKey struct{}

// NewContextWithSkipTokenReuse creates a new context from ctx and attaches a
// value to skip the token reuse.
func NewContextWithSkipTokenReuse(ctx context.Context) context.Context {
	return context.WithValue(ctx, skipTokenReuseKey{}, true)
}

// SkipTokenReuseFromContext returns if the token reuse needs to be ignored.
func SkipTokenReuseFromContext(ctx context.Context) bool {
	m, _ := ctx.Value(skipTokenReuseKey{}).(bool)
	return m
}

// authorizeToken parses the token and returns the provisioner used to generate
// the token. This method enforces the One-Time use policy (tokens can only be
// used once).
func (a *Authority) authorizeToken(ctx context.Context, ott string) (provisioner.Interface, error) {
	var opts = []errs.Option{errs.WithCtxKeyVal("ott", ott)}

	// Validate payload
	token, err := jose.ParseSigned(ott)
	if err != nil {
		return nil, errs.Wrap(http.StatusUnauthorized, err, "authorizeToken: error parsing token", opts...)
	}

	// Get claims w/out verification. We need to look up the provisioner
	// key in order to verify the claims and we need the issuer from the claims
	// before we can look up the provisioner.
	var claims Claims
	if err = token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, errs.Wrap(http.StatusUnauthorized, err, "authorizeToken", opts...)
	}

	// TODO: use new persistence layer abstraction.
	// Do not accept tokens issued before the start of the ca.
	// This check is meant as a stopgap solution to the current lack of a persistence layer.
	if a.config.AuthorityConfig != nil && !a.config.AuthorityConfig.DisableIssuedAtCheck {
		if claims.IssuedAt != nil && claims.IssuedAt.Time().Before(a.startTime) {
			return nil, errs.Unauthorized(errors.New("authorizeToken: token issued before the bootstrap of certificate authority"), opts...)
		}
	}

	// This method will also validate the audiences for JWK provisioners.
	p, ok := a.provisioners.LoadByToken(token, &claims.Claims)
	if !ok {
		return nil, errs.Unauthorized(errors.Errorf("authorizeToken: provisioner "+
			"not found or invalid audience (%s)", strings.Join(claims.Audience, ", ")), opts...)
	}

	// Store the token to protect against reuse unless it's skipped.
	if !SkipTokenReuseFromContext(ctx) {
		if reuseKey, err := p.GetTokenID(ott); err == nil {
			ok, err := a.db.UseToken(reuseKey, ott)
			if err != nil {
				return nil, errs.Wrap(http.StatusInternalServerError, err,
					"authorizeToken: failed when attempting to store token", opts...)
			}
			if !ok {
				return nil, errs.Unauthorized(errors.Errorf("authorizeToken: token already used"), opts...)
			}
		}
	}

	return p, nil
}

// Authorize grabs the method from the context and authorizes a signature
// request by validating the one-time-token.
func (a *Authority) Authorize(ctx context.Context, ott string) ([]provisioner.SignOption, error) {
	var opts = []errs.Option{errs.WithCtxKeyVal("ott", ott)}

	switch m := provisioner.MethodFromContext(ctx); m {
	case provisioner.SignMethod:
		return a.authorizeSign(ctx, ott)
	case provisioner.RevokeMethod:
		return nil, a.authorizeRevoke(ctx, ott)
	case provisioner.SignSSHMethod:
		if a.sshCAHostCertSignKey == nil && a.sshCAUserCertSignKey == nil {
			return nil, errs.NotImplemented(errors.New("authorize: ssh certificate flows are not enabled"), opts...)
		}
		return a.authorizeSSHSign(ctx, ott)
	case provisioner.RenewSSHMethod:
		if a.sshCAHostCertSignKey == nil && a.sshCAUserCertSignKey == nil {
			return nil, errs.NotImplemented(errors.New("authorize: ssh certificates flows are not enabled"), opts...)
		}
		if _, err := a.authorizeSSHRenew(ctx, ott); err != nil {
			return nil, err
		}
		return nil, nil
	case provisioner.RevokeSSHMethod:
		return nil, a.authorizeSSHRevoke(ctx, ott)
	case provisioner.RekeySSHMethod:
		if a.sshCAHostCertSignKey == nil && a.sshCAUserCertSignKey == nil {
			return nil, errs.NotImplemented(errors.New("authorize: ssh certificates flows are not enabled"), opts...)
		}
		_, opts, err := a.authorizeSSHRekey(ctx, ott)
		if err != nil {
			return nil, err
		}
		return opts, nil
	default:
		return nil, errs.InternalServerError(errors.Errorf("authorize: method %d is not supported", m), opts...)
	}
}

// authorizeSign loads the provisioner from the token and calls the provisioner
// AuthorizeSign method. Returns a list of methods to apply to the signing flow.
func (a *Authority) authorizeSign(ctx context.Context, ott string) ([]provisioner.SignOption, error) {
	var opts = []errs.Option{errs.WithCtxKeyVal("ott", ott)}

	p, err := a.authorizeToken(ctx, ott)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "authority.authorizeSign", opts...)
	}
	signOpts, err := p.AuthorizeSign(ctx, ott)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "authority.authorizeSign", opts...)
	}
	return signOpts, nil
}

// AuthorizeSign authorizes a signature request by validating and authenticating
// a OTT that must be sent w/ the request.
//
// NOTE: This method is deprecated and should not be used. We make it available
// in the short term os as not to break existing clients.
func (a *Authority) AuthorizeSign(ott string) ([]provisioner.SignOption, error) {
	ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.SignMethod)
	return a.Authorize(ctx, ott)
}

// authorizeRevoke locates the provisioner used to generate the authenticating
// token and then performs the token validation flow.
func (a *Authority) authorizeRevoke(ctx context.Context, ott string) error {
	var opts = []errs.Option{errs.WithCtxKeyVal("ott", ott)}

	p, err := a.authorizeToken(ctx, ott)
	if err != nil {
		return errs.Wrap(http.StatusInternalServerError, err, "authority.authorizeRevoke", opts...)
	}
	if err = p.AuthorizeRevoke(ctx, ott); err != nil {
		return errs.Wrap(http.StatusInternalServerError, err, "authority.authorizeRevoke", opts...)
	}
	return nil
}

// authorizeRenew locates the provisioner (using the provisioner extension in the cert), and checks
// if for the configured provisioner, the renewal is enabled or not. If the
// extra extension cannot be found, authorize the renewal by default.
//
// TODO(mariano): should we authorize by default?
func (a *Authority) authorizeRenew(cert *x509.Certificate) error {
	var opts = []errs.Option{errs.WithCtxKeyVal("serialNumber", cert.SerialNumber.String())}

	// Check the passive revocation table.
	isRevoked, err := a.db.IsRevoked(cert.SerialNumber.String())
	if err != nil {
		return errs.Wrap(http.StatusInternalServerError, err, "authority.authorizeRenew", opts...)
	}
	if isRevoked {
		return errs.Unauthorized(errors.New("authority.authorizeRenew: certificate has been revoked"), opts...)
	}

	p, ok := a.provisioners.LoadByCertificate(cert)
	if !ok {
		return errs.Unauthorized(errors.New("authority.authorizeRenew: provisioner not found"), opts...)
	}
	if err := p.AuthorizeRenew(context.Background(), cert); err != nil {
		return errs.Wrap(http.StatusInternalServerError, err, "authority.authorizeRenew", opts...)
	}
	return nil
}
