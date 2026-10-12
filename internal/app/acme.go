package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"
)

const renewBefore = 30 * 24 * time.Hour

// NeedsRenewal reports whether less than 30 days remain (or the cert is unusable).
func NeedsRenewal(leaf *x509.Certificate, now time.Time) bool {
	return leaf == nil || leaf.NotAfter.Sub(now) < renewBefore
}

// CertManager obtains and renews the certificate via ACME HTTP-01.
type CertManager struct {
	Dir          string // DATA_DIR/acme
	Domain       string
	Email        string
	DirectoryURL string
	HTTPClient   *http.Client
	Now          func() time.Time

	mu         sync.Mutex
	challenges map[string]string // token path -> key authorization
	cert       atomic.Pointer[tls.Certificate]
}

func NewCertManager(dataDir, domain, email, dirURL string, now func() time.Time) *CertManager {
	return &CertManager{
		Dir: filepath.Join(dataDir, "acme"), Domain: domain, Email: email, DirectoryURL: dirURL,
		Now: now, challenges: map[string]string{},
	}
}

func (c *CertManager) Certificate() *tls.Certificate { return c.cert.Load() }

func (c *CertManager) Leaf() *x509.Certificate {
	if cert := c.cert.Load(); cert != nil {
		return cert.Leaf
	}
	return nil
}

// Expiry returns the NotAfter of the current certificate.
func (c *CertManager) Expiry() (time.Time, bool) {
	if l := c.Leaf(); l != nil {
		return l.NotAfter, true
	}
	return time.Time{}, false
}

// Valid reports whether a certificate for the domain that is not expired is loaded.
func (c *CertManager) Valid() bool {
	l := c.Leaf()
	return l != nil && c.Now().Before(l.NotAfter) && l.VerifyHostname(c.Domain) == nil
}

func (c *CertManager) ChallengeHandler(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	v, ok := c.challenges[r.URL.Path]
	c.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, v)
}

func (c *CertManager) setChallenge(path, v string) {
	c.mu.Lock()
	c.challenges[path] = v
	c.mu.Unlock()
}

func (c *CertManager) clearChallenge(path string) {
	c.mu.Lock()
	delete(c.challenges, path)
	c.mu.Unlock()
}

// LoadStored loads the stored certificate, if any.
func (c *CertManager) LoadStored() error {
	cert, err := tls.LoadX509KeyPair(filepath.Join(c.Dir, "cert.pem"), filepath.Join(c.Dir, "key.pem"))
	if err != nil {
		return err
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	if cert.Leaf.VerifyHostname(c.Domain) != nil {
		return errors.New("stored certificate does not match domain")
	}
	c.cert.Store(&cert)
	return nil
}

func writePEMFile(path string, blocks ...*pem.Block) error {
	var out []byte
	for _, b := range blocks {
		out = append(out, pem.EncodeToMemory(b)...)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (c *CertManager) accountKey() (*ecdsa.PrivateKey, error) {
	path := filepath.Join(c.Dir, "account.key")
	if b, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, errors.New("account.key is corrupt")
		}
		return x509.ParseECPrivateKey(blk.Bytes)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, _ := x509.MarshalECPrivateKey(k)
	return k, writePEMFile(path, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// Obtain runs one full ACME order and stores the resulting certificate.
func (c *CertManager) Obtain(ctx context.Context) error {
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return err
	}
	acctKey, err := c.accountKey()
	if err != nil {
		return err
	}
	client := &acme.Client{Key: acctKey, DirectoryURL: c.DirectoryURL, HTTPClient: c.HTTPClient, UserAgent: "secure-notes/" + Version}
	acct := &acme.Account{}
	if c.Email != "" {
		acct.Contact = []string{"mailto:" + c.Email}
	}
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("register: %w", err)
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(c.Domain))
	if err != nil {
		return fmt.Errorf("new order: %w", err)
	}
	for _, zurl := range order.AuthzURLs {
		z, err := client.GetAuthorization(ctx, zurl)
		if err != nil {
			return fmt.Errorf("get authorization: %w", err)
		}
		if z.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, ch := range z.Challenges {
			if ch.Type == "http-01" {
				chal = ch
			}
		}
		if chal == nil {
			return errors.New("no http-01 challenge offered")
		}
		resp, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return err
		}
		path := client.HTTP01ChallengePath(chal.Token)
		c.setChallenge(path, resp)
		err = func() error {
			defer c.clearChallenge(path)
			if _, err := client.Accept(ctx, chal); err != nil {
				return fmt.Errorf("accept challenge: %w", err)
			}
			if _, err := client.WaitAuthorization(ctx, zurl); err != nil {
				return fmt.Errorf("authorization: %w", err)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	if _, err := client.WaitOrder(ctx, order.URI); err != nil {
		return fmt.Errorf("order: %w", err)
	}
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: c.Domain}, DNSNames: []string{c.Domain},
	}, certKey)
	if err != nil {
		return err
	}
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("finalize: %w", err)
	}
	if len(der) == 0 {
		return errors.New("empty certificate chain")
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return err
	}
	if err := leaf.VerifyHostname(c.Domain); err != nil {
		return fmt.Errorf("issued certificate: %w", err)
	}
	var blocks []*pem.Block
	for _, d := range der {
		blocks = append(blocks, &pem.Block{Type: "CERTIFICATE", Bytes: d})
	}
	kder, _ := x509.MarshalECPrivateKey(certKey)
	if err := writePEMFile(filepath.Join(c.Dir, "key.pem"), &pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}); err != nil {
		return err
	}
	if err := writePEMFile(filepath.Join(c.Dir, "cert.pem"), blocks...); err != nil {
		return err
	}
	return c.LoadStored()
}

// Run loads the stored certificate and keeps it fresh until ctx is cancelled.
// onChange is called after every successful load or renewal.
func (c *CertManager) Run(ctx context.Context, onChange func(), checkEvery, minBackoff, maxBackoff time.Duration) {
	if err := c.LoadStored(); err == nil {
		Event("acme_certificate_loaded")
		onChange()
	}
	backoff := minBackoff
	for {
		wait := checkEvery
		if NeedsRenewal(c.Leaf(), c.Now()) {
			err := c.Obtain(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				Event("acme_failed", "error", strings.ReplaceAll(err.Error(), "\n", " "))
				wait = backoff
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			} else {
				exp, _ := c.Expiry()
				Event("acme_certificate_issued", "expires_at", exp.UTC().Format(time.RFC3339))
				backoff = minBackoff
				onChange()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}
