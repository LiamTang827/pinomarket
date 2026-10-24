package live

import (
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// HTTPRouteTelemetry measures application handler boundaries, not wire traffic.
// Request bytes are bytes actually read, response bytes are accepted by Write,
// and elapsed handler time includes IO/queue/model waits. It is not CPU time.
// Status 0 means a handler unwound without producing a final HTTP status.
type HTTPRouteTelemetry struct {
	Requests          int64            `json:"requests"`
	RequestBodyBytes  int64            `json:"request_body_bytes"`
	ResponseBodyBytes int64            `json:"response_body_bytes"`
	HandlerMSTotal    float64          `json:"handler_ms_total"`
	HandlerMSMax      float64          `json:"handler_ms_max"`
	Failures          int64            `json:"failures"`
	Aborted           int64            `json:"aborted"`
	StatusCodes       map[string]int64 `json:"status_codes"`
}

type NodeTelemetry struct {
	Schema           int                           `json:"schema"`
	Node             string                        `json:"node"`
	ProcessStartedAt string                        `json:"process_started_at"`
	HTTP             map[string]HTTPRouteTelemetry `json:"http"`
	Limitations      string                        `json:"limitations"`
}

var measuredHTTPRoutes = []string{"/submit", "/gossip", "/open", "/state", "/health"}

const telemetryLimitations = "Cumulative per-process application HTTP body counters, attributed when a handler completes or unwinds; in-flight handlers are absent, and interval-crossing handlers contribute their entire body at completion. Request bytes count only bytes read by handlers; responses count bytes accepted by ResponseWriter. Excludes headers, TCP/framing, CometBFT P2P/RPC, model traffic and /metrics itself. /state and /health are observer overhead, separate from /submit, /gossip and /open. Handler elapsed time includes waiting and is not CPU time. Counters reset after process restart."

type nodeTelemetry struct {
	mu      sync.Mutex
	started string
	node    string
	http    map[string]HTTPRouteTelemetry
}

func newNodeTelemetry(node string) *nodeTelemetry {
	t := &nodeTelemetry{node: node, started: time.Now().UTC().Format(time.RFC3339Nano), http: make(map[string]HTTPRouteTelemetry)}
	for _, route := range measuredHTTPRoutes {
		t.http[route] = HTTPRouteTelemetry{StatusCodes: make(map[string]int64)}
	}
	return t
}

func (t *nodeTelemetry) snapshot(node string) NodeTelemetry {
	out := NodeTelemetry{Schema: 1, Node: node, HTTP: make(map[string]HTTPRouteTelemetry), Limitations: telemetryLimitations}
	if t == nil {
		for _, route := range measuredHTTPRoutes {
			out.HTTP[route] = HTTPRouteTelemetry{StatusCodes: make(map[string]int64)}
		}
		return out
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out.Node, out.ProcessStartedAt = t.node, t.started
	for route, stats := range t.http {
		stats.StatusCodes = make(map[string]int64, len(t.http[route].StatusCodes))
		for code, count := range t.http[route].StatusCodes {
			stats.StatusCodes[code] = count
		}
		out.HTTP[route] = stats
	}
	return out
}

type countedBody struct {
	io.ReadCloser
	bytes int64
}

func (b *countedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.bytes += int64(n)
	return n, err
}

type countedResponse struct {
	http.ResponseWriter
	status int
	bytes  int64
}

// Unwrap lets http.ResponseController reach the underlying ResponseWriter.
func (w *countedResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *countedResponse) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	if status >= 100 && status < 200 {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *countedResponse) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

// wrap only admits fixed route labels. It never stores request URLs, payloads,
// ciphertexts, signatures, wallet identities, or model responses.
func (t *nodeTelemetry) wrap(route string, next http.HandlerFunc) http.HandlerFunc {
	if t == nil {
		return next
	}
	known := false
	for _, measured := range measuredHTTPRoutes {
		known = known || measured == route
	}
	if !known {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		var body *countedBody
		if r.Body != nil {
			body = &countedBody{ReadCloser: r.Body}
			r.Body = body
		}
		response := &countedResponse{ResponseWriter: w}
		returned := false
		defer func() {
			elapsed := float64(time.Since(started)) / float64(time.Millisecond)
			status := response.status
			if status == 0 && returned {
				status = http.StatusOK
			}
			t.mu.Lock()
			defer t.mu.Unlock()
			stats := t.http[route]
			stats.Requests++
			if body != nil {
				stats.RequestBodyBytes += body.bytes
			}
			stats.ResponseBodyBytes += response.bytes
			stats.HandlerMSTotal += elapsed
			if elapsed > stats.HandlerMSMax {
				stats.HandlerMSMax = elapsed
			}
			stats.StatusCodes[strconv.Itoa(status)]++
			if status >= 400 || !returned {
				stats.Failures++
			}
			if !returned {
				stats.Aborted++
			}
			t.http[route] = stats
		}()
		next(response, r)
		returned = true
	}
}

func (n *liveNode) metrics(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	sendJSON(w, http.StatusOK, n.telemetry.snapshot(n.peer.ID))
}

func (n *liveNode) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", n.telemetry.wrap("/health", n.health))
	mux.HandleFunc("/state", n.telemetry.wrap("/state", n.state))
	mux.HandleFunc("/submit", n.telemetry.wrap("/submit", n.submit))
	mux.HandleFunc("/gossip", n.telemetry.wrap("/gossip", n.gossip))
	mux.HandleFunc("/open", n.telemetry.wrap("/open", n.open))
	mux.HandleFunc("/metrics", n.metrics)
	return mux
}
