package app

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeGoogle struct {
	t      *testing.T
	srv    *httptest.Server
	key    *rsa.PrivateKey
	mu     sync.Mutex
	tokens map[string]map[string]any // code -> claims
	last   url.Values                // last token request form
}

func newFakeGoogle(t *testing.T) *fakeGoogle {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	g := &fakeGoogle{t: t, key: key, tokens: map[string]map[string]any{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		g.mu.Lock()
		g.last = r.PostForm
		claims, ok := g.tokens[r.PostForm.Get("code")]
		g.mu.Unlock()
		if !ok || r.PostForm.Get("client_secret") != "test-secret" {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"id_token": g.sign(claims), "access_token": "x"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": b64.EncodeToString(key.N.Bytes()), "e": "AQAB",
		}}})
	})
	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGoogle) endpoints() GoogleEndpoints {
	return GoogleEndpoints{AuthURL: g.srv.URL + "/auth", TokenURL: g.srv.URL + "/token", JWKSURL: g.srv.URL + "/jwks"}
}

func (g *fakeGoogle) sign(claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	p, _ := json.Marshal(claims)
	in := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	d := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, g.key, crypto.SHA256, d[:])
	if err != nil {
		g.t.Fatal(err)
	}
	return in + "." + b64.EncodeToString(sig)
}

func (g *fakeGoogle) claims(sub, email string, mod func(map[string]any)) map[string]any {
	c := map[string]any{"iss": "https://accounts.google.com", "aud": "test-client", "sub": sub, "email": email,
		"email_verified": true, "name": "User " + sub, "exp": time.Now().Add(time.Hour).Unix()}
	if mod != nil {
		mod(c)
	}
	return c
}

func (g *fakeGoogle) addCode(code string, claims map[string]any) {
	g.mu.Lock()
	g.tokens[code] = claims
	g.mu.Unlock()
}

type testEnv struct {
	t   *testing.T
	app *App
	srv *httptest.Server
	g   *fakeGoogle
	dir string
}

func testSettings(dir string) Settings {
	return Settings{HTTPPort: "0", HTTPSPort: "0", DataDir: dir, SecretName: "secure-notes/config", DevInsecureHTTP: true,
		VolumeStateFile: dir + "/none", Env: map[string]string{"DOMAIN": "notes.test", "GOOGLE_CLIENT_ID": "test-client", "GOOGLE_CLIENT_SECRET": "test-secret"}}
}

func newTestEnv(t *testing.T) *testEnv {
	g := newFakeGoogle(t)
	dir := t.TempDir()
	a := New(Options{Settings: testSettings(dir), Google: g.endpoints(), RetryInitial: time.Millisecond, RetryMax: 5 * time.Millisecond})
	if err := a.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(func() { srv.Close(); a.store.Close() })
	return &testEnv{t: t, app: a, srv: srv, g: g, dir: dir}
}

type client struct {
	*http.Client
	base string
	t    *testing.T
}

func (e *testEnv) newClient() *client {
	jar, _ := cookiejar.New(nil)
	return &client{Client: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, base: e.srv.URL, t: e.t}
}

func (c *client) do(method, path string, body any) (int, map[string]any, string) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m, string(raw)
}

// startLogin performs GET /auth/google and returns the state and the redirect location.
func (c *client) startLogin() (state string, loc *url.URL) {
	resp, err := c.Get(c.base + "/auth/google")
	if err != nil {
		c.t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 {
		c.t.Fatalf("start login status %d", resp.StatusCode)
	}
	loc, _ = url.Parse(resp.Header.Get("Location"))
	return loc.Query().Get("state"), loc
}

func (c *client) callback(state, code string) *http.Response {
	resp, err := c.Get(c.base + "/auth/google/callback?state=" + url.QueryEscape(state) + "&code=" + url.QueryEscape(code))
	if err != nil {
		c.t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func (e *testEnv) login(sub, email string) *client {
	c := e.newClient()
	code := "code-" + sub
	e.g.addCode(code, e.g.claims(sub, email, nil))
	state, _ := c.startLogin()
	resp := c.callback(state, code)
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/app" {
		e.t.Fatalf("login %s: status %d loc %s", sub, resp.StatusCode, resp.Header.Get("Location"))
	}
	return c
}

func newReq(method, u, body string) (*http.Request, error) {
	req, err := http.NewRequest(method, u, strings.NewReader(body))
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, err
}
