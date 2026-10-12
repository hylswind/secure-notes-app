package app

import (
	"crypto/sha256"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestLoginFlow(t *testing.T) {
	e := newTestEnv(t)
	c := e.newClient()
	if code, body, _ := c.do("GET", "/api/me", nil); code != 401 || body["error"] != "unauthorized" {
		t.Fatalf("unauth api: %d %v", code, body)
	}
	resp, _ := c.Get(c.base + "/app")
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/" {
		t.Fatalf("unauth page: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	e.g.addCode("c1", e.g.claims("sub-12345678", "Alice@Example.com", nil))
	state, loc := c.startLogin()
	q := loc.Query()
	if !strings.HasPrefix(loc.String(), e.g.srv.URL+"/auth") || q.Get("scope") != "openid email profile" ||
		q.Get("code_challenge_method") != "S256" || q.Get("client_id") != "test-client" || q.Get("response_type") != "code" {
		t.Fatalf("bad authorization redirect %s", loc)
	}
	resp = c.callback(state, "c1")
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/app" {
		t.Fatalf("callback: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	var sess string
	for _, ck := range resp.Cookies() {
		if ck.Name == SessionCookie {
			sess = ck.Value
			if !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode || ck.MaxAge != 14*24*3600 {
				t.Errorf("cookie attrs %+v", ck)
			}
		}
	}
	if sess == "" {
		t.Fatal("no session cookie")
	}
	// PKCE: verifier sent to the token endpoint hashes to the challenge.
	e.g.mu.Lock()
	v := e.g.last.Get("code_verifier")
	e.g.mu.Unlock()
	h := sha256.Sum256([]byte(v))
	if b64.EncodeToString(h[:]) != q.Get("code_challenge") {
		t.Error("PKCE verifier does not match challenge")
	}
	code, me, _ := c.do("GET", "/api/me", nil)
	if code != 200 || me["email"] != "alice@example.com" || me["sub_suffix"] != "345678" || me["name"] != "User sub-12345678" {
		t.Fatalf("me %d %v", code, me)
	}
	// landing redirects when signed in
	resp, _ = c.Get(c.base + "/")
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/app" {
		t.Fatalf("landing: %d", resp.StatusCode)
	}
	if code, _, _ := c.do("POST", "/auth/logout", nil); code != 200 {
		t.Fatalf("logout %d", code)
	}
	if code, _, _ := c.do("GET", "/api/me", nil); code != 401 {
		t.Fatalf("after logout %d", code)
	}
}

func TestLoginRejections(t *testing.T) {
	e := newTestEnv(t)
	cases := map[string]func(map[string]any){
		"aud":      func(m map[string]any) { m["aud"] = "someone-else" },
		"expired":  func(m map[string]any) { m["exp"] = time.Now().Add(-time.Minute).Unix() },
		"unverif":  func(m map[string]any) { m["email_verified"] = false },
		"issuer":   func(m map[string]any) { m["iss"] = "https://evil.example" },
		"no-email": func(m map[string]any) { delete(m, "email") },
	}
	for name, mod := range cases {
		c := e.newClient()
		e.g.addCode(name, e.g.claims("s-"+name, name+"@example.com", mod))
		state, _ := c.startLogin()
		resp := c.callback(state, name)
		if resp.StatusCode < 400 {
			t.Errorf("%s: status %d", name, resp.StatusCode)
		}
		if code, _, _ := c.do("GET", "/api/me", nil); code != 401 {
			t.Errorf("%s: session issued", name)
		}
	}
	// bad state
	c := e.newClient()
	e.g.addCode("ok", e.g.claims("s-ok", "ok@example.com", nil))
	c.startLogin()
	if resp := c.callback("forged", "ok"); resp.StatusCode != 400 {
		t.Errorf("bad state: %d", resp.StatusCode)
	}
	// no state cookie at all
	c2 := e.newClient()
	if resp := c2.callback("x", "ok"); resp.StatusCode != 400 {
		t.Errorf("missing cookie: %d", resp.StatusCode)
	}
	// unknown code
	c3 := e.newClient()
	st, _ := c3.startLogin()
	if resp := c3.callback(st, "nope"); resp.StatusCode < 400 {
		t.Errorf("bad code: %d", resp.StatusCode)
	}
	// metrics counted failures and none succeeded
	_, _, raw := e.newClient().do("GET", "/metrics", nil)
	if !strings.Contains(raw, `logins_total{result="failure"}`) || !strings.Contains(raw, `logins_total{result="success"} 0`) {
		t.Errorf("metrics:\n%s", raw)
	}
}

func TestSessionCookie(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 1
	now := time.Now()
	tok, err := SignSession(key, "sub1", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if sub, err := VerifySession(key, tok, now); err != nil || sub != "sub1" {
		t.Fatalf("verify: %v %v", sub, err)
	}
	// tampered payload
	other, _ := SignSession(key, "sub2", now.Add(time.Hour))
	forged := strings.Split(other, ".")[0] + "." + strings.Split(tok, ".")[1]
	if _, err := VerifySession(key, forged, now); err == nil {
		t.Error("forged token accepted")
	}
	if _, err := VerifySession(key, tok+"x", now); err == nil {
		t.Error("tampered mac accepted")
	}
	if _, err := VerifySession(key, "garbage", now); err == nil {
		t.Error("garbage accepted")
	}
	// wrong key
	key2 := make([]byte, 32)
	if _, err := VerifySession(key2, tok, now); err == nil {
		t.Error("wrong key accepted")
	}
	// expiry
	if _, err := VerifySession(key, tok, now.Add(2*time.Hour)); err == nil {
		t.Error("expired token accepted")
	}
	// a state-cookie token must not verify as a session
	st, _ := sign(key, "oauth", sessionClaims{Sub: "x", Exp: now.Add(time.Hour).Unix()})
	if _, err := VerifySession(key, st, now); err == nil {
		t.Error("purpose confusion")
	}
}

func TestKeysPersist(t *testing.T) {
	dir := t.TempDir()
	k1, err := loadOrCreateKey(dir)
	if err != nil || len(k1) != 32 {
		t.Fatal(err)
	}
	k2, _ := loadOrCreateKey(dir)
	if string(k1) != string(k2) {
		t.Error("key not reused")
	}
}
