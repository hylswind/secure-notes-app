package app

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed web
var webFS embed.FS

type Options struct {
	Settings     Settings
	Secrets      func(ctx context.Context) (SecretFetcher, error)
	Google       GoogleEndpoints
	HTTPClient   *http.Client // for Google
	ACMEClient   *http.Client
	Now          func() time.Time
	RetryInitial time.Duration
	RetryMax     time.Duration
}

type App struct {
	set        Settings
	secrets    func(context.Context) (SecretFetcher, error)
	google     GoogleEndpoints
	httpClient *http.Client
	acmeClient *http.Client
	now        func() time.Time
	retryMin   time.Duration
	retryMax   time.Duration

	metrics *Metrics
	jwks    jwksCache

	cfgPtr     atomic.Pointer[Config]
	core       atomic.Bool // config, key and database are in place
	store      *Store
	sessionKey []byte
	certs      *CertManager

	httpsOnce sync.Once
	httpsSrv  *http.Server
	mu        sync.Mutex
}

func New(o Options) *App {
	a := &App{
		set: o.Settings, secrets: o.Secrets, google: o.Google, httpClient: o.HTTPClient, acmeClient: o.ACMEClient,
		now: o.Now, retryMin: o.RetryInitial, retryMax: o.RetryMax, metrics: NewMetrics(),
	}
	if a.secrets == nil {
		a.secrets = NewAWSSecrets
	}
	if a.google.AuthURL == "" {
		a.google = DefaultGoogle()
	}
	if a.httpClient == nil {
		a.httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	if a.now == nil {
		a.now = time.Now
	}
	if a.retryMin == 0 {
		a.retryMin = time.Second
	}
	if a.retryMax == 0 {
		a.retryMax = time.Minute
	}
	return a
}

func (a *App) config() Config { return *a.cfgPtr.Load() }

func (a *App) Store() *Store { return a.store }

// Ready reports whether configuration, data directory, database and (outside dev mode) certificate are in place.
func (a *App) Ready() bool {
	if !a.core.Load() {
		return false
	}
	return a.set.DevInsecureHTTP || (a.certs != nil && a.certs.Valid())
}

// Initialize resolves the configuration and opens the data directory, retrying with
// exponential backoff until it succeeds or ctx is cancelled.
func (a *App) Initialize(ctx context.Context) error {
	err := retryResolve(ctx, a.tryInit, a.retryMin, a.retryMax, func(attempt int, err error) {
		Event("init_failed", "attempt", attempt, "error", strings.ReplaceAll(err.Error(), "\n", " "))
	})
	if err != nil {
		return err
	}
	Event("config_resolved", "ready", true)
	return nil
}

func (a *App) tryInit(ctx context.Context) error {
	if a.cfgPtr.Load() == nil {
		c, err := ResolveConfig(ctx, a.set.Env, a.secrets, a.set.SecretName)
		if err != nil {
			return err
		}
		a.cfgPtr.Store(&c)
	}
	if a.store == nil {
		if err := os.MkdirAll(a.set.DataDir, 0o700); err != nil {
			return err
		}
		key, err := loadOrCreateKey(a.set.DataDir)
		if err != nil {
			return err
		}
		st, err := OpenStore(a.set.DataDir)
		if err != nil {
			return err
		}
		a.sessionKey, a.store = key, st
	}
	if !a.set.DevInsecureHTTP && a.certs == nil {
		c := a.config()
		cm := NewCertManager(a.set.DataDir, c.Domain, c.ACMEEmail, c.ACMEDirectoryURL, a.now)
		cm.HTTPClient = a.acmeClient
		a.certs = cm
	}
	a.core.Store(true)
	return nil
}

// Purge removes notes trashed more than 30 days ago.
func (a *App) Purge() {
	n, err := a.store.PurgeTrash(a.now())
	if err != nil {
		Event("purge_failed", "error", err.Error())
		return
	}
	Event("purge", "removed", n)
}

func (a *App) volumeState() (string, string) {
	if a.set.DevInsecureHTTP {
		return "DEV", ""
	}
	b, err := os.ReadFile(a.set.VolumeStateFile)
	if err != nil {
		return "REFUSED", "volume state unavailable"
	}
	lines := strings.SplitN(strings.TrimSpace(string(b)), "\n", 2)
	state := strings.TrimSpace(lines[0])
	reason := ""
	if len(lines) > 1 {
		reason = strings.TrimSpace(lines[1])
	}
	switch state {
	case "UNLOCKED", "ENROLLED", "REFUSED":
		return state, reason
	}
	return "REFUSED", "unknown volume state"
}

func volumeNumber(s string) int {
	switch s {
	case "UNLOCKED":
		return 1
	case "ENROLLED":
		return 2
	case "REFUSED":
		return 3
	case "DEV":
		return 4
	}
	return 0
}

// ---- HTTP plumbing ----

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(c int) {
	if s.status == 0 {
		s.status = c
	}
	s.ResponseWriter.WriteHeader(c)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = 200
	}
	return s.ResponseWriter.Write(b)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (a *App) instrument(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; base-uri 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
			if o := r.Header.Get("Origin"); o != "" {
				if u, err := url.Parse(o); err != nil || u.Host != r.Host {
					httpError(sw, 403, "cross-origin request refused")
					a.record(r, sw, start)
					return
				}
			}
		}
		mux.ServeHTTP(sw, r)
		a.record(r, sw, start)
	})
}

func (a *App) record(r *http.Request, sw *statusWriter, start time.Time) {
	route := "unmatched"
	if r.Pattern != "" {
		route = r.Pattern
		if i := strings.IndexByte(route, ' '); i >= 0 {
			route = route[i+1:]
		}
	}
	if sw.status == 0 {
		sw.status = 200
	}
	a.metrics.Request(r.Method, route, itoa(sw.status))
	logJSON(map[string]any{"method": r.Method, "route": route, "status": sw.status,
		"duration_ms": float64(time.Since(start).Microseconds()) / 1000})
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

// gated answers 503 until the configuration and database are available.
func (a *App) gated(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.core.Load() {
			httpError(w, http.StatusServiceUnavailable, "not ready")
			return
		}
		h(w, r)
	}
}

func (a *App) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("ok\n"))
}

func (a *App) handleReady(w http.ResponseWriter, r *http.Request) {
	if a.Ready() {
		writeJSON(w, 200, map[string]any{"ready": true})
		return
	}
	writeJSON(w, 503, map[string]any{"ready": false})
}

func (a *App) handleMetrics(w http.ResponseWriter, r *http.Request) {
	var notes int64
	if a.core.Load() {
		notes, _ = a.store.CountNotes()
	}
	var expiry float64
	if a.certs != nil {
		if t, ok := a.certs.Expiry(); ok {
			expiry = t.Sub(a.now()).Seconds()
		}
	}
	st, _ := a.volumeState()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	a.metrics.Write(w, notes, expiry, volumeNumber(st))
}

// Handler is the full application (served on HTTPS, or on HTTP in dev mode).
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.handleHealthz)
	mux.HandleFunc("GET /ready", a.handleReady)
	mux.HandleFunc("GET /metrics", a.handleMetrics)
	mux.HandleFunc("GET /.well-known/acme-challenge/{token}", a.handleChallenge)
	mux.HandleFunc("GET /auth/google", a.gated(a.handleGoogleStart))
	mux.HandleFunc("GET /auth/google/callback", a.gated(a.handleGoogleCallback))
	mux.HandleFunc("POST /auth/logout", a.gated(a.handleLogout))
	a.pageRoutes(mux)
	a.apiRoutes(mux)
	mux.HandleFunc("/", a.gated(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			httpError(w, 404, "not found")
			return
		}
		http.NotFound(w, r)
	}))
	return a.instrument(mux)
}

func (a *App) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if a.certs == nil {
		http.NotFound(w, r)
		return
	}
	a.certs.ChallengeHandler(w, r)
}

// HTTPHandler is served on the plain HTTP port: ACME challenges, health, and redirects to HTTPS.
func (a *App) HTTPHandler() http.Handler {
	if a.set.DevInsecureHTTP {
		return a.Handler()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.handleHealthz)
	mux.HandleFunc("GET /ready", a.handleReady)
	mux.HandleFunc("GET /.well-known/acme-challenge/{token}", a.handleChallenge)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !a.core.Load() {
			httpError(w, http.StatusServiceUnavailable, "not ready")
			return
		}
		host := a.config().Domain
		if p := a.set.HTTPSPort; p != "443" {
			host = net.JoinHostPort(host, p)
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
	return a.instrument(mux)
}

func (a *App) startHTTPS(ctx context.Context) {
	a.httpsOnce.Do(func() {
		srv := &http.Server{
			Handler:           a.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					if c := a.certs.Certificate(); c != nil {
						return c, nil
					}
					return nil, errors.New("no certificate")
				},
			},
		}
		a.mu.Lock()
		a.httpsSrv = srv
		a.mu.Unlock()
		ln, err := net.Listen("tcp", "0.0.0.0:"+a.set.HTTPSPort)
		if err != nil {
			Event("https_listen_failed", "error", err.Error())
			return
		}
		Event("https_started", "port", a.set.HTTPSPort)
		go func() {
			if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				Event("https_failed", "error", err.Error())
			}
		}()
	})
}

// Run starts the listeners and background work, and blocks until ctx is cancelled.
func (a *App) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", "0.0.0.0:"+a.set.HTTPPort)
	if err != nil {
		return err
	}
	return a.RunWithListener(ctx, ln)
}

func (a *App) RunWithListener(ctx context.Context, ln net.Listener) error {
	httpSrv := &http.Server{Handler: a.HTTPHandler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			Event("http_failed", "error", err.Error())
		}
	}()
	Event("http_started", "addr", ln.Addr().String(), "dev", a.set.DevInsecureHTTP)

	bg, cancelBG := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if a.Initialize(bg) != nil {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.purgeLoop(bg)
		}()
		if !a.set.DevInsecureHTTP {
			a.certs.Run(bg, func() { a.startHTTPS(bg) }, 24*time.Hour, time.Minute, time.Hour)
		}
	}()

	<-ctx.Done()
	Event("shutting_down")
	cancelBG()
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(sctx)
	a.mu.Lock()
	hs := a.httpsSrv
	a.mu.Unlock()
	if hs != nil {
		_ = hs.Shutdown(sctx)
	}
	wg.Wait()
	if a.store != nil {
		_ = a.store.Close()
	}
	return nil
}

func (a *App) purgeLoop(ctx context.Context) {
	for {
		a.Purge()
		select {
		case <-ctx.Done():
			return
		case <-time.After(24 * time.Hour):
		}
	}
}

func mustSub() fs.FS {
	sub, err := fs.Sub(webFS, "web/static")
	if err != nil {
		panic(err)
	}
	return sub
}
