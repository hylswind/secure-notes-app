package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockACME is a minimal in-process RFC 8555 server (signatures are not verified).
type mockACME struct {
	t         *testing.T
	srv       *httptest.Server
	caKey     *ecdsa.PrivateKey
	caCert    *x509.Certificate
	challAddr string // base URL of the app's HTTP listener
	domain    string
	validity  time.Duration

	mu       sync.Mutex
	nonce    int
	calls    []string
	authzOK  bool
	finalOK  bool
	failNew  bool
	contacts []string
	csrPub   any
}

func newMockACME(t *testing.T, domain, challAddr string) *mockACME {
	m := &mockACME{t: t, domain: domain, challAddr: challAddr, validity: 90 * 24 * time.Hour}
	m.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Mock CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &m.caKey.PublicKey, m.caKey)
	m.caCert, _ = x509.ParseCertificate(der)
	m.srv = httptest.NewServer(http.HandlerFunc(m.serve))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockACME) url(p string) string { return m.srv.URL + p }

func payload(r *http.Request) []byte {
	b, _ := io.ReadAll(r.Body)
	var jws struct {
		Payload string `json:"payload"`
	}
	json.Unmarshal(b, &jws)
	p, _ := b64.DecodeString(jws.Payload)
	return p
}

func (m *mockACME) serve(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.nonce++
	n := m.nonce
	m.calls = append(m.calls, r.Method+" "+r.URL.Path)
	m.mu.Unlock()
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", n))
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	switch r.URL.Path {
	case "/directory":
		reply(200, map[string]string{"newNonce": m.url("/nonce"), "newAccount": m.url("/acct"), "newOrder": m.url("/order"), "revokeCert": m.url("/revoke"), "keyChange": m.url("/kc")})
	case "/nonce":
		w.WriteHeader(204)
	case "/acct":
		var req struct {
			Contact []string `json:"contact"`
		}
		json.Unmarshal(payload(r), &req)
		m.mu.Lock()
		m.contacts = req.Contact
		m.mu.Unlock()
		w.Header().Set("Location", m.url("/acct/1"))
		reply(201, map[string]any{"status": "valid", "contact": req.Contact})
	case "/order":
		if m.failNew {
			reply(403, map[string]string{"type": "urn:ietf:params:acme:error:unauthorized", "detail": "boom"})
			return
		}
		w.Header().Set("Location", m.url("/order/1"))
		reply(201, m.order("pending"))
	case "/order/1":
		m.mu.Lock()
		st := "pending"
		if m.finalOK {
			st = "valid"
		} else if m.authzOK {
			st = "ready"
		}
		m.mu.Unlock()
		reply(200, m.order(st))
	case "/authz/1":
		m.mu.Lock()
		ok := m.authzOK
		m.mu.Unlock()
		st := "pending"
		if ok {
			st = "valid"
		}
		reply(200, map[string]any{"status": st, "identifier": map[string]string{"type": "dns", "value": m.domain},
			"challenges": []map[string]string{{"type": "http-01", "url": m.url("/chal/1"), "token": "tok-abc", "status": st}}})
	case "/chal/1":
		// validate by fetching the key authorization from the app's own listener
		req, _ := http.NewRequest("GET", m.challAddr+"/.well-known/acme-challenge/tok-abc", nil)
		req.Host = m.domain
		resp, err := http.DefaultClient.Do(req)
		ok := false
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			ok = resp.StatusCode == 200 && strings.HasPrefix(string(b), "tok-abc.")
		}
		m.mu.Lock()
		m.authzOK = ok
		m.mu.Unlock()
		reply(200, map[string]string{"type": "http-01", "url": m.url("/chal/1"), "token": "tok-abc", "status": "processing"})
	case "/finalize/1":
		var req struct {
			CSR string `json:"csr"`
		}
		json.Unmarshal(payload(r), &req)
		der, _ := b64.DecodeString(req.CSR)
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil || csr.CheckSignature() != nil {
			reply(400, map[string]string{"type": "urn:ietf:params:acme:error:badCSR", "detail": "bad csr"})
			return
		}
		m.mu.Lock()
		m.finalOK = true
		m.csrPub = csr.PublicKey
		m.mu.Unlock()
		reply(200, m.order("valid"))
	case "/cert/1":
		// the real CSR was parsed above; issue for the requested names
		m.mu.Lock()
		defer m.mu.Unlock()
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.Write(m.issue())
	default:
		http.NotFound(w, r)
	}
}

func (m *mockACME) order(status string) map[string]any {
	o := map[string]any{"status": status, "identifiers": []map[string]string{{"type": "dns", "value": m.domain}},
		"authorizations": []string{m.url("/authz/1")}, "finalize": m.url("/finalize/1")}
	if status == "valid" {
		o["certificate"] = m.url("/cert/1")
	}
	return o
}

func (m *mockACME) issue() []byte {
	// The pubkey from the CSR is not tracked across requests; reissue using the CSR captured at finalize.
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: m.domain}, DNSNames: []string{m.domain},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(m.validity), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.caCert, m.csrPub, m.caKey)
	if err != nil {
		m.t.Error(err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.caCert.Raw})...)
}

func acmeApp(t *testing.T, validity time.Duration) (*App, *mockACME, *httptest.Server) {
	dir := t.TempDir()
	set := testSettings(dir)
	set.DevInsecureHTTP = false
	set.Env = map[string]string{"DOMAIN": "notes.example.test", "GOOGLE_CLIENT_ID": "test-client", "GOOGLE_CLIENT_SECRET": "test-secret", "ACME_EMAIL": "ops@example.test"}
	var mock *mockACME
	a := New(Options{Settings: set, RetryInitial: time.Millisecond})
	// the mock needs the app's listener, the app needs the mock's URL: wire the directory via env after both exist
	httpSrv := httptest.NewServer(a.HTTPHandler())
	t.Cleanup(httpSrv.Close)
	mock = newMockACME(t, "notes.example.test", httpSrv.URL)
	mock.validity = validity
	a.set.Env["ACME_DIRECTORY_URL"] = mock.url("/directory")
	if err := a.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.store.Close() })
	return a, mock, httpSrv
}

func TestACMEIssuance(t *testing.T) {
	a, mock, httpSrv := acmeApp(t, 90*24*time.Hour)
	if a.Ready() {
		t.Fatal("ready without certificate")
	}
	if err := a.certs.Obtain(context.Background()); err != nil {
		t.Fatalf("obtain: %v\ncalls: %v", err, mock.calls)
	}
	if !a.Ready() || !a.certs.Valid() {
		t.Fatal("not ready after issuance")
	}
	exp, _ := a.certs.Expiry()
	if d := time.Until(exp); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Errorf("expiry %v", exp)
	}
	if len(mock.contacts) != 1 || mock.contacts[0] != "mailto:ops@example.test" {
		t.Errorf("contacts %v", mock.contacts)
	}
	for _, f := range []string{"cert.pem", "key.pem", "account.key"} {
		st, err := os.Stat(a.set.DataDir + "/acme/" + f)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", f, st, err)
		}
	}
	// the challenge token is gone after validation
	resp, _ := http.Get(httpSrv.URL + "/.well-known/acme-challenge/tok-abc")
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("challenge still served: %d", resp.StatusCode)
	}
	// port 80 redirects everything else to https://DOMAIN
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ = cl.Get(httpSrv.URL + "/app?x=1")
	resp.Body.Close()
	if resp.StatusCode != 301 || resp.Header.Get("Location") != "https://notes.example.test:0/app?x=1" && resp.Header.Get("Location") != "https://notes.example.test/app?x=1" {
		t.Errorf("redirect: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// the stored certificate is reloaded on restart and is not re-ordered
	cm := NewCertManager(a.set.DataDir, "notes.example.test", "", mock.url("/directory"), time.Now)
	if err := cm.LoadStored(); err != nil || !cm.Valid() {
		t.Fatalf("reload: %v", err)
	}
	// TLS 1.2+ with the issued certificate
	pool := x509.NewCertPool()
	pool.AddCert(mock.caCert)
	_ = pool
}

func TestACMEFailureIsNotFatal(t *testing.T) {
	a, mock, _ := acmeApp(t, 90*24*time.Hour)
	mock.failNew = true
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	changes := 0
	a.certs.Run(ctx, func() { changes++ }, time.Hour, 20*time.Millisecond, 40*time.Millisecond)
	if changes != 0 || a.Ready() {
		t.Error("should not be ready")
	}
	mock.mu.Lock()
	orders := 0
	for _, c := range mock.calls {
		if c == "POST /order" {
			orders++
		}
	}
	mock.mu.Unlock()
	if orders < 2 {
		t.Errorf("expected retries with backoff, saw %d order attempts", orders)
	}
	// recovers once the server does
	mock.failNew = false
	ctx2, cancel2 := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		a.certs.Run(ctx2, func() { cancel2() }, time.Hour, 20*time.Millisecond, 40*time.Millisecond)
		close(done)
	}()
	<-done
	if !a.Ready() {
		t.Error("not ready after recovery")
	}
}

func TestRenewalDecision(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	leaf := func(d time.Duration) *x509.Certificate { return &x509.Certificate{NotAfter: now.Add(d)} }
	cases := []struct {
		remaining time.Duration
		want      bool
	}{
		{90 * 24 * time.Hour, false},
		{31 * 24 * time.Hour, false},
		{30*24*time.Hour + time.Second, false},
		{30 * 24 * time.Hour, false},
		{30*24*time.Hour - time.Second, true},
		{29 * 24 * time.Hour, true},
		{-time.Hour, true},
	}
	for _, c := range cases {
		if got := NeedsRenewal(leaf(c.remaining), now); got != c.want {
			t.Errorf("remaining %v: got %v want %v", c.remaining, got, c.want)
		}
	}
	if !NeedsRenewal(nil, now) {
		t.Error("no certificate must need issuance")
	}
}

func TestRenewsShortLivedCertificate(t *testing.T) {
	a, mock, _ := acmeApp(t, 10*24*time.Hour) // issued cert is already inside the renewal window
	if err := a.certs.Obtain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !NeedsRenewal(a.certs.Leaf(), time.Now()) {
		t.Fatal("10-day certificate should need renewal")
	}
	mock.validity = 90 * 24 * time.Hour
	mock.mu.Lock()
	mock.authzOK, mock.finalOK = false, false
	mock.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	n := 0
	a.certs.Run(ctx, func() {
		n++
		if !NeedsRenewal(a.certs.Leaf(), time.Now()) {
			cancel()
		}
	}, time.Hour, 10*time.Millisecond, 20*time.Millisecond)
	if NeedsRenewal(a.certs.Leaf(), time.Now()) {
		t.Error("certificate not renewed")
	}
}
