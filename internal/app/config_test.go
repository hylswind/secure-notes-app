package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type mockSecrets struct {
	calls atomic.Int32
	fails int32
	value string
}

func (m *mockSecrets) GetSecretString(ctx context.Context, name string) (string, error) {
	n := m.calls.Add(1)
	if n <= m.fails {
		return "", errors.New("throttled")
	}
	if name != "secure-notes/config" {
		return "", errors.New("wrong secret name " + name)
	}
	return m.value, nil
}

func fetcher(m *mockSecrets) func(context.Context) (SecretFetcher, error) {
	return func(context.Context) (SecretFetcher, error) { return m, nil }
}

const secretValue = `{"domain":"secret.example","google_client_id":"sid","google_client_secret":"ssecret","acme_email":"ops@example.com","acme_directory_url":"https://acme.test/dir"}`

func TestResolveConfig(t *testing.T) {
	ctx := context.Background()
	// environment complete: Secrets Manager is not consulted
	m := &mockSecrets{value: secretValue}
	c, err := ResolveConfig(ctx, map[string]string{"DOMAIN": "env.example", "GOOGLE_CLIENT_ID": "eid", "GOOGLE_CLIENT_SECRET": "esecret"}, fetcher(m), "secure-notes/config")
	if err != nil || c.Domain != "env.example" || m.calls.Load() != 0 {
		t.Fatalf("env only: %+v %v calls=%d", c, err, m.calls.Load())
	}
	if c.ACMEDirectoryURL != "https://acme-v02.api.letsencrypt.org/directory" {
		t.Errorf("default directory %s", c.ACMEDirectoryURL)
	}
	// environment overrides the secret, the secret fills the rest
	c, err = ResolveConfig(ctx, map[string]string{"DOMAIN": "env.example"}, fetcher(m), "secure-notes/config")
	if err != nil || c.Domain != "env.example" || c.GoogleClientID != "sid" || c.GoogleSecret != "ssecret" || c.ACMEEmail != "ops@example.com" || c.ACMEDirectoryURL != "https://acme.test/dir" {
		t.Fatalf("merge: %+v %v", c, err)
	}
	// secret problems
	for _, bad := range []string{`not json`, `{"domain":"x"}`} {
		if _, err := ResolveConfig(ctx, map[string]string{}, fetcher(&mockSecrets{value: bad}), "secure-notes/config"); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := ResolveConfig(ctx, map[string]string{}, fetcher(&mockSecrets{value: secretValue}), "other/name"); err == nil {
		t.Error("secret name not passed through")
	}
}

func TestNotReadyThenReady(t *testing.T) {
	m := &mockSecrets{value: secretValue, fails: 3}
	dir := t.TempDir()
	set := testSettings(dir)
	set.Env = map[string]string{}
	a := New(Options{Settings: set, Secrets: fetcher(m), RetryInitial: 20 * time.Millisecond, RetryMax: 40 * time.Millisecond})
	srv := httptest.NewServer(a.HTTPHandler())
	defer srv.Close()
	get := func(p string) (int, string) {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b := make([]byte, 200)
		n, _ := resp.Body.Read(b)
		return resp.StatusCode, string(b[:n])
	}
	if code, _ := get("/healthz"); code != 200 {
		t.Errorf("healthz before config: %d", code)
	}
	if code, _ := get("/ready"); code != 503 {
		t.Errorf("ready before config: %d", code)
	}
	for _, p := range []string{"/", "/app", "/api/me", "/auth/google", "/static/app.js"} {
		code, body := get(p)
		if code != 503 || strings.TrimSpace(body) != `{"error":"not ready"}` {
			t.Errorf("%s before config: %d %q", p, code, body)
		}
	}
	done := make(chan error, 1)
	go func() { done <- a.Initialize(context.Background()) }()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	defer a.store.Close()
	if m.calls.Load() != 4 {
		t.Errorf("expected 3 failures then success, calls=%d", m.calls.Load())
	}
	if code, _ := get("/ready"); code != 200 {
		t.Errorf("ready after config: %d", code)
	}
	if code, _ := get("/"); code != 200 {
		t.Errorf("landing after config: %d", code)
	}
	if _, err := os.Stat(dir + "/keys.json"); err != nil {
		t.Errorf("keys.json: %v", err)
	}
	if st, _ := os.Stat(dir + "/keys.json"); st.Mode().Perm() != 0o600 {
		t.Errorf("keys.json mode %v", st.Mode())
	}
}

func TestInitializeCancel(t *testing.T) {
	m := &mockSecrets{value: secretValue, fails: 1 << 30}
	set := testSettings(t.TempDir())
	set.Env = map[string]string{}
	a := New(Options{Settings: set, Secrets: fetcher(m), RetryInitial: time.Millisecond, RetryMax: 2 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := a.Initialize(ctx); err == nil {
		t.Fatal("expected cancellation")
	}
	if m.calls.Load() < 3 {
		t.Errorf("did not retry: %d", m.calls.Load())
	}
}

func TestMetricsAndStatus(t *testing.T) {
	e := newTestEnv(t)
	c := e.login("u1", "u1@example.com")
	mustNote(t, c, map[string]any{"title": "x"})
	code, st, _ := c.do("GET", "/api/status", nil)
	if code != 200 || st["volume"] != "DEV" || st["version"] != Version || st["certificate_expires_at"] != nil {
		t.Fatalf("status %d %v", code, st)
	}
	if _, ok := st["volume_reason"]; !ok {
		t.Error("volume_reason missing")
	}
	if code, _, _ := e.newClient().do("GET", "/api/status", nil); code != 401 {
		t.Errorf("status unauth: %d", code)
	}
	_, _, m := c.do("GET", "/metrics", nil)
	for _, want := range []string{
		`# TYPE http_requests_total counter`,
		`http_requests_total{method="POST",route="/api/notes",status="201"} 1`,
		`logins_total{result="success"} 1`,
		"notes_total 1\n",
		"acme_certificate_expiry_seconds 0\n",
		"data_volume_state 4\n",
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics missing %q\n%s", want, m)
		}
	}
	// non-dev volume states come from the state file
	for state, num := range map[string]string{"UNLOCKED": "1", "ENROLLED": "2", "REFUSED": "3"} {
		e.app.set.DevInsecureHTTP = false
		os.WriteFile(e.app.set.VolumeStateFile, []byte(state+"\nbecause\n"), 0o644)
		_, st, _ := c.do("GET", "/api/status", nil)
		if st["volume"] != state || st["volume_reason"] != "because" {
			t.Errorf("%s: %v", state, st)
		}
		_, _, m := c.do("GET", "/metrics", nil)
		if !strings.Contains(m, "data_volume_state "+num+"\n") {
			t.Errorf("%s metric", state)
		}
	}
	e.app.set.DevInsecureHTTP = true
}

func TestSecurityHeadersAndPages(t *testing.T) {
	e := newTestEnv(t)
	c := e.login("u1", "u1@example.com")
	for _, p := range []string{"/", "/app", "/app/settings", "/static/app.js", "/static/style.css", "/static/md.js"} {
		resp, err := c.Get(c.base + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		want := 200
		if p == "/" {
			want = 302
		}
		if resp.StatusCode != want {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
		if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'self'") {
			t.Errorf("%s: missing CSP", p)
		}
	}
	if code, b, _ := c.do("GET", "/api/nothing", nil); code != 404 || b["error"] == nil {
		t.Errorf("unknown api: %d", code)
	}
}
