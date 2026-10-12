package app

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// GoogleEndpoints are overridable so tests can point at a fake Google.
type GoogleEndpoints struct {
	AuthURL  string
	TokenURL string
	JWKSURL  string
}

func DefaultGoogle() GoogleEndpoints {
	return GoogleEndpoints{
		AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL: "https://oauth2.googleapis.com/token",
		JWKSURL:  "https://www.googleapis.com/oauth2/v3/certs",
	}
}

type idClaims struct {
	Iss           string `json:"iss"`
	Aud           any    `json:"aud"`
	Sub           string `json:"sub"`
	Exp           int64  `json:"exp"`
	Email         string `json:"email"`
	EmailVerified any    `json:"email_verified"`
	Name          string `json:"name"`
}

type jwksCache struct {
	mu   sync.Mutex
	keys map[string]*rsa.PublicKey
	at   time.Time
}

func (j *jwksCache) get(ctx context.Context, hc *http.Client, url, kid string, force bool) (*rsa.PublicKey, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if k, ok := j.keys[kid]; ok && !force && time.Since(j.at) < time.Hour {
		return k, nil
	}
	if j.keys != nil && time.Since(j.at) < 30*time.Second {
		if k, ok := j.keys[kid]; ok {
			return k, nil
		}
		return nil, errors.New("unknown signing key")
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("jwks: status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		n, err1 := b64.DecodeString(k.N)
		e, err2 := b64.DecodeString(k.E)
		if err1 != nil || err2 != nil {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	j.keys, j.at = keys, time.Now()
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, errors.New("unknown signing key")
}

func (a *App) verifyIDToken(ctx context.Context, token string, cfg Config) (*idClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed id_token")
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("malformed id_token header")
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &h); err != nil || h.Alg != "RS256" {
		return nil, errors.New("unsupported id_token algorithm")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("malformed id_token signature")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	var verr error
	for _, force := range []bool{false, true} {
		var pub *rsa.PublicKey
		pub, verr = a.jwks.get(ctx, a.httpClient, a.google.JWKSURL, h.Kid, force)
		if verr != nil {
			continue
		}
		if verr = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); verr == nil {
			break
		}
	}
	if verr != nil {
		return nil, fmt.Errorf("id_token signature: %v", verr)
	}
	pb, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed id_token payload")
	}
	var c idClaims
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, errors.New("malformed id_token payload")
	}
	if c.Iss != "accounts.google.com" && c.Iss != "https://accounts.google.com" {
		return nil, errors.New("bad issuer")
	}
	okAud := false
	switch v := c.Aud.(type) {
	case string:
		okAud = v == cfg.GoogleClientID
	case []any:
		for _, x := range v {
			if s, _ := x.(string); s == cfg.GoogleClientID {
				okAud = true
			}
		}
	}
	if !okAud {
		return nil, errors.New("bad audience")
	}
	if a.now().Unix() >= c.Exp {
		return nil, errors.New("id_token expired")
	}
	verified := false
	switch v := c.EmailVerified.(type) {
	case bool:
		verified = v
	case string:
		verified = v == "true"
	}
	if !verified || c.Email == "" {
		return nil, errors.New("email not verified")
	}
	if c.Sub == "" {
		return nil, errors.New("missing subject")
	}
	return &c, nil
}

func (a *App) redirectURI(cfg Config) string {
	scheme := "https"
	if a.set.DevInsecureHTTP {
		scheme = "http"
	}
	return scheme + "://" + cfg.Domain + "/auth/google/callback"
}

func (a *App) secureCookies() bool { return !a.set.DevInsecureHTTP }

func (a *App) handleGoogleStart(w http.ResponseWriter, r *http.Request) {
	cfg := a.config()
	state, verifier := randomString(24), randomString(32)
	tok, err := sign(a.sessionKey, "oauth", oauthState{State: state, Verifier: verifier, Exp: a.now().Add(10 * time.Minute).Unix()})
	if err != nil {
		httpError(w, 500, "internal error")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: StateCookie, Value: tok, Path: "/auth/google/callback", MaxAge: 600,
		HttpOnly: true, Secure: a.secureCookies(), SameSite: http.SameSiteLaxMode})
	ch := sha256.Sum256([]byte(verifier))
	q := url.Values{}
	q.Set("client_id", cfg.GoogleClientID)
	q.Set("redirect_uri", a.redirectURI(cfg))
	q.Set("response_type", "code")
	q.Set("scope", "openid email profile")
	q.Set("state", state)
	q.Set("code_challenge", b64.EncodeToString(ch[:]))
	q.Set("code_challenge_method", "S256")
	q.Set("prompt", "select_account")
	http.Redirect(w, r, a.google.AuthURL+"?"+q.Encode(), http.StatusFound)
}

func (a *App) loginFail(w http.ResponseWriter, reason string, code int) {
	a.metrics.Login("failure")
	Event("login_failed", "reason", reason)
	http.SetCookie(w, &http.Cookie{Name: StateCookie, Value: "", Path: "/auth/google/callback", MaxAge: -1})
	httpError(w, code, "login failed")
}

func (a *App) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	cfg := a.config()
	c, err := r.Cookie(StateCookie)
	if err != nil {
		a.loginFail(w, "missing state cookie", 400)
		return
	}
	var st oauthState
	if err := verify(a.sessionKey, "oauth", c.Value, &st); err != nil || a.now().Unix() >= st.Exp {
		a.loginFail(w, "invalid state cookie", 400)
		return
	}
	got := r.URL.Query().Get("state")
	if got == "" || got != st.State {
		a.loginFail(w, "state mismatch", 400)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		a.loginFail(w, "no code: "+r.URL.Query().Get("error"), 400)
		return
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", a.redirectURI(cfg))
	form.Set("client_id", cfg.GoogleClientID)
	form.Set("client_secret", cfg.GoogleSecret)
	form.Set("code_verifier", st.Verifier)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", a.google.TokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		a.loginFail(w, "token request failed", 502)
		return
	}
	defer resp.Body.Close()
	var tr struct {
		IDToken string `json:"id_token"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr) != nil || tr.IDToken == "" {
		a.loginFail(w, fmt.Sprintf("token exchange status %d", resp.StatusCode), 502)
		return
	}
	claims, err := a.verifyIDToken(ctx, tr.IDToken, cfg)
	if err != nil {
		a.loginFail(w, err.Error(), 401)
		return
	}
	name := claims.Name
	if name == "" {
		name = claims.Email
	}
	if err := a.store.UpsertUser(User{Sub: claims.Sub, Email: claims.Email, Name: name}, a.now()); err != nil {
		a.loginFail(w, "store error", 500)
		return
	}
	exp := a.now().Add(SessionTTL)
	tok, err := SignSession(a.sessionKey, claims.Sub, exp)
	if err != nil {
		a.loginFail(w, "sign error", 500)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: StateCookie, Value: "", Path: "/auth/google/callback", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: tok, Path: "/", Expires: exp, MaxAge: int(SessionTTL.Seconds()),
		HttpOnly: true, Secure: a.secureCookies(), SameSite: http.SameSiteLaxMode})
	a.metrics.Login("success")
	Event("login_succeeded")
	http.Redirect(w, r, "/app", http.StatusFound)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: a.secureCookies(), SameSite: http.SameSiteLaxMode})
	writeJSON(w, 200, map[string]any{"ok": true})
}
