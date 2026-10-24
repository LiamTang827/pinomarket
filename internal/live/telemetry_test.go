package live

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestHTTPMeasurementCountsConsumedBytesAndFirstStatus(t *testing.T) {
	stats := newNodeTelemetry("node-1")
	handler := stats.wrap("/submit", func(w http.ResponseWriter, r *http.Request) {
		buffer := make([]byte, 3)
		if _, err := io.ReadFull(r.Body, buffer); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusAccepted)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("hello"))
	})
	w := httptest.NewRecorder()
	handler(w, httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader("longer body than read")))
	snapshot := stats.snapshot("")
	got := snapshot.HTTP["/submit"]
	if got.Requests != 1 || got.RequestBodyBytes != 3 || got.ResponseBodyBytes != 5 || got.StatusCodes["202"] != 1 || got.Failures != 0 || w.Code != http.StatusAccepted {
		t.Fatalf("unexpected counters/status: %+v, response=%d", got, w.Code)
	}
	if got.HandlerMSTotal <= 0 || got.HandlerMSMax != got.HandlerMSTotal || snapshot.ProcessStartedAt == "" || snapshot.Node != "node-1" {
		t.Fatalf("missing identity or duration: %+v", snapshot)
	}
	// Returned snapshots must not alias a map still updated by the server.
	got.StatusCodes["202"] = 999
	if stats.snapshot("").HTTP["/submit"].StatusCodes["202"] != 1 {
		t.Fatal("snapshot leaked the live status counter map")
	}
}

func TestHTTPMeasurementCountsFailuresAndKeepsObserversSeparate(t *testing.T) {
	stats := newNodeTelemetry("node-1")
	stats.wrap("/gossip", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		sendError(w, http.StatusBadRequest, io.ErrUnexpectedEOF)
	})(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/gossip", strings.NewReader("bad")))
	stats.wrap("/state", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("state snapshot"))
	})(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/state", nil))
	s := stats.snapshot("")
	if s.HTTP["/gossip"].Failures != 1 || s.HTTP["/gossip"].RequestBodyBytes != 3 || s.HTTP["/gossip"].StatusCodes["400"] != 1 {
		t.Fatalf("failed request omitted: %+v", s.HTTP["/gossip"])
	}
	if s.HTTP["/state"].Requests != 1 || s.HTTP["/submit"].Requests != 0 || s.HTTP["/state"].ResponseBodyBytes != int64(len("state snapshot")) {
		t.Fatalf("observer route mixed with protocol requests: %+v", s.HTTP)
	}
}

func TestHTTPMetricsEndpointDoesNotCountItself(t *testing.T) {
	stats := newNodeTelemetry("node-1")
	n := &liveNode{peer: Peer{ID: "node-1"}, telemetry: stats}
	mux := n.routes()
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		var snapshot NodeTelemetry
		if err := json.Unmarshal(w.Body.Bytes(), &snapshot); err != nil || w.Code != http.StatusOK {
			t.Fatalf("invalid metric response: %v status=%d", err, w.Code)
		}
		if _, exists := snapshot.HTTP["/metrics"]; exists {
			t.Fatal("metric polling counted itself")
		}
		for route, counter := range snapshot.HTTP {
			if counter.Requests != 0 {
				t.Fatalf("poll changed %s counters: %+v", route, counter)
			}
		}
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("metrics accepts mutation method: %d", w.Code)
	}
	// Unit tests often construct nodes without telemetry; they remain usable.
	bare := &liveNode{peer: Peer{ID: "bare"}}
	w = httptest.NewRecorder()
	bare.routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("nil metrics failed: %d", w.Code)
	}
}

func TestHTTPMeasurementsAreConcurrentAndDoNotSwallowPanics(t *testing.T) {
	stats := newNodeTelemetry("node-1")
	handler := stats.wrap("/open", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	var workers sync.WaitGroup
	for i := 0; i < 50; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			handler(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/open", nil))
			_ = stats.snapshot("")
		}()
	}
	workers.Wait()
	if got := stats.snapshot("").HTTP["/open"]; got.Requests != 50 || got.ResponseBodyBytes != 100 || got.StatusCodes["200"] != 50 {
		t.Fatalf("lost concurrent counter updates: %+v", got)
	}
	func() {
		defer func() {
			if recover() != "original panic" {
				t.Error("middleware changed panic behavior")
			}
		}()
		stats.wrap("/submit", func(http.ResponseWriter, *http.Request) { panic("original panic") })(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/submit", nil))
	}()
	if got := stats.snapshot("").HTTP["/submit"]; got.Requests != 1 || got.Failures != 1 || got.Aborted != 1 || got.StatusCodes["0"] != 1 {
		t.Fatalf("aborted handler not identified: %+v", got)
	}
}
