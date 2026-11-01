package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/baldoseri/tracehound/internal/api"
	"github.com/baldoseri/tracehound/internal/capture"
	"github.com/baldoseri/tracehound/internal/pcapgen"
	"github.com/baldoseri/tracehound/internal/session"
)

func TestSessionEndpointReportsLifecycleAndFinalCounters(t *testing.T) {
	analysis, err := session.New(session.Options{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := api.NewSession(analysis, 0)
	handler := srv.Handler()
	readSnapshot := func() session.Snapshot {
		t.Helper()
		r := httptest.NewRecorder()
		handler.ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/api/session", nil))
		if r.Code != http.StatusOK {
			t.Fatalf("GET /api/session: %d %s", r.Code, r.Body.String())
		}
		var snapshot session.Snapshot
		if err := json.Unmarshal(r.Body.Bytes(), &snapshot); err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	if got := readSnapshot(); got.State != session.Ready || got.StartedAt != nil || got.FinishedAt != nil {
		t.Fatalf("ready endpoint response = %+v", got)
	}

	path := filepath.Join(t.TempDir(), "demo.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := pcapgen.Write(f, captureStart)
	closeErr := f.Close()
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	src, err := capture.OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	stats, err := analysis.Run(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	got := readSnapshot()
	if got.State != session.Completed || got.StartedAt == nil || got.FinishedAt == nil {
		t.Fatalf("completed endpoint response = %+v", got)
	}
	if stats.Packets == 0 || got.Stats.Packets != stats.Packets || got.Rules.Total != 7 {
		t.Errorf("endpoint lost analysis results: %+v", got)
	}
}

func TestSessionEndpointWithoutSessionReturnsNotFound(t *testing.T) {
	srv, _ := newSensor(t)
	r := httptest.NewRecorder()
	srv.Handler().ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/api/session", nil))
	if r.Code != http.StatusNotFound {
		t.Errorf("GET /api/session without lifecycle: %d, want 404", r.Code)
	}
}
