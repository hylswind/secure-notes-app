package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type Metrics struct {
	mu       sync.Mutex
	requests map[[3]string]int64
	logins   map[string]int64
}

func NewMetrics() *Metrics {
	return &Metrics{requests: map[[3]string]int64{}, logins: map[string]int64{}}
}

func (m *Metrics) Request(method, route, status string) {
	m.mu.Lock()
	m.requests[[3]string{method, route, status}]++
	m.mu.Unlock()
}

func (m *Metrics) Login(result string) {
	m.mu.Lock()
	m.logins[result]++
	m.mu.Unlock()
}

func esc(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// Write renders the Prometheus text exposition format.
func (m *Metrics) Write(w io.Writer, notes int64, certExpirySeconds float64, volumeState int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprintln(w, "# HELP http_requests_total HTTP requests by method, route and status.")
	fmt.Fprintln(w, "# TYPE http_requests_total counter")
	keys := make([][3]string, 0, len(m.requests))
	for k := range m.requests {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		return a[0]+"\x00"+a[1]+"\x00"+a[2] < b[0]+"\x00"+b[1]+"\x00"+b[2]
	})
	for _, k := range keys {
		fmt.Fprintf(w, "http_requests_total{method=\"%s\",route=\"%s\",status=\"%s\"} %d\n", esc(k[0]), esc(k[1]), esc(k[2]), m.requests[k])
	}
	fmt.Fprintln(w, "# HELP logins_total Google login attempts by result.")
	fmt.Fprintln(w, "# TYPE logins_total counter")
	for _, r := range []string{"success", "failure"} {
		fmt.Fprintf(w, "logins_total{result=\"%s\"} %d\n", r, m.logins[r])
	}
	fmt.Fprintln(w, "# HELP notes_total Notes stored (not in trash).")
	fmt.Fprintln(w, "# TYPE notes_total gauge")
	fmt.Fprintf(w, "notes_total %d\n", notes)
	fmt.Fprintln(w, "# HELP acme_certificate_expiry_seconds Seconds until the TLS certificate expires (0 when none).")
	fmt.Fprintln(w, "# TYPE acme_certificate_expiry_seconds gauge")
	fmt.Fprintf(w, "acme_certificate_expiry_seconds %.0f\n", certExpirySeconds)
	fmt.Fprintln(w, "# HELP data_volume_state 0 unknown, 1 unlocked, 2 enrolled, 3 refused, 4 dev.")
	fmt.Fprintln(w, "# TYPE data_volume_state gauge")
	fmt.Fprintf(w, "data_volume_state %d\n", volumeState)
}

var logMu sync.Mutex

// logJSON writes one JSON log line to stdout.
func logJSON(fields map[string]any) {
	fields["time"] = time.Now().UTC().Format(time.RFC3339Nano)
	b, err := json.Marshal(fields)
	if err != nil {
		return
	}
	logMu.Lock()
	defer logMu.Unlock()
	os.Stdout.Write(append(b, '\n'))
}

// Event logs a background event.
func Event(event string, kv ...any) {
	f := map[string]any{"event": event}
	for i := 0; i+1 < len(kv); i += 2 {
		f[fmt.Sprint(kv[i])] = kv[i+1]
	}
	logJSON(f)
}
