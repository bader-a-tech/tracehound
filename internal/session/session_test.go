package session_test

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/baldoseri/tracehound/internal/capture"
	"github.com/baldoseri/tracehound/internal/model"
	"github.com/baldoseri/tracehound/internal/pcapgen"
	"github.com/baldoseri/tracehound/internal/pipeline"
	"github.com/baldoseri/tracehound/internal/session"
)

func newSession(t *testing.T) *session.Session {
	t.Helper()
	s, err := session.New(session.Options{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// This checks the shared assembly path, including rule tuning and policy,
// rather than constructing detectors individually as the pipeline tests do.
func TestBuiltInReplayFindsAttacksWithoutAccusingBenignHosts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "demo.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	groundTruth, err := pcapgen.Write(f, time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC))
	closeErr := f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	src, err := capture.OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	var alerts []model.Alert
	s, err := session.New(session.Options{AlertCooldown: 24 * time.Hour}, func(a model.Alert) {
		alerts = append(alerts, a)
	})
	if err != nil {
		t.Fatal(err)
	}
	stats, err := s.Run(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	if len(groundTruth.Expected) == 0 {
		t.Fatal("capture has no planted behaviours")
	}
	attacker := make(map[string]bool)
	for _, expected := range groundTruth.Expected {
		attacker[expected.Src] = true
		found := false
		for _, a := range alerts {
			if a.RuleID == expected.RuleID && a.Src.String() == expected.Src {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missed %s from %s", expected.RuleID, expected.Src)
		}
	}
	benign := make(map[string]bool)
	for _, host := range groundTruth.Hosts {
		if !attacker[host] {
			benign[host] = true
		}
	}
	if len(benign) == 0 {
		t.Fatal("capture has no benign hosts")
	}
	for _, a := range alerts {
		if a.Severity >= model.SevLow && benign[a.Src.String()] {
			t.Errorf("%s accused benign host %s", a.RuleID, a.Src)
		}
	}
	snapshot := s.Snapshot()
	if snapshot.State != session.Completed || snapshot.StartedAt == nil || snapshot.FinishedAt == nil {
		t.Fatalf("finished snapshot = %+v", snapshot)
	}
	if stats.Packets == 0 || snapshot.Stats.Packets != stats.Packets || snapshot.Stats.Bytes != stats.Bytes {
		t.Errorf("final counters disagree: snapshot %+v, Run %+v", snapshot.Stats, stats)
	}
	if snapshot.Rules.Total != 7 || snapshot.Rules.Enabled != 7 || snapshot.Rules.Origin != "built-in" {
		t.Errorf("rule summary = %+v", snapshot.Rules)
	}
	if len(s.Inventory().Devices()) == 0 {
		t.Error("session did not expose the inventory populated during replay")
	}
}

// A live read may take time to acknowledge interruption. Keeping that window
// open lets this test exercise stopping state and concurrent readers reliably.
type blockingSource struct {
	entered     chan struct{}
	interrupted chan struct{}
	allowStop   chan struct{}
	release     chan struct{}
	enterOnce   sync.Once
	stopOnce    sync.Once
	releaseOnce sync.Once
}

func (s *blockingSource) Next() (model.Packet, error) {
	s.enterOnce.Do(func() { close(s.entered) })
	<-s.release
	return model.Packet{}, capture.ErrDone
}
func (s *blockingSource) Interrupt() error {
	s.stopOnce.Do(func() { close(s.interrupted) })
	<-s.allowStop
	s.releaseOnce.Do(func() { close(s.release) })
	return nil
}
func (s *blockingSource) LinkType() string     { return "Ethernet" }
func (s *blockingSource) Stats() capture.Stats { return capture.Stats{} }
func (s *blockingSource) Close() error         { return nil }

func await(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestStopTracksLifecycleAndRejectsConcurrentRuns(t *testing.T) {
	s := newSession(t)
	ready := s.Snapshot()
	if ready.State != session.Ready || ready.StartedAt != nil || ready.FinishedAt != nil || s.Stop() {
		t.Fatalf("initial snapshot = %+v", ready)
	}
	src := &blockingSource{
		entered: make(chan struct{}), interrupted: make(chan struct{}),
		allowStop: make(chan struct{}), release: make(chan struct{}),
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(src.allowStop) }) }
	t.Cleanup(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := s.Run(ctx, src)
		done <- err
	}()
	await(t, src.entered, "capture read")
	running := s.Snapshot()
	if running.State != session.Running || running.StartedAt == nil || running.FinishedAt != nil {
		t.Fatalf("running snapshot = %+v", running)
	}
	started := *running.StartedAt
	*running.StartedAt = started.Add(-time.Hour)
	if got := s.Snapshot().StartedAt; got == nil || !got.Equal(started) {
		t.Error("caller mutated the session's start time through a snapshot")
	}
	if _, err := s.Run(context.Background(), &scriptedSource{}); !errors.Is(err, session.ErrAlreadyRun) {
		t.Errorf("concurrent Run error = %v, want ErrAlreadyRun", err)
	}
	if !s.Stop() || !s.Stop() {
		t.Fatal("Stop did not accept repeated requests while stopping")
	}
	await(t, src.interrupted, "source interruption")
	if got := s.Snapshot().State; got != session.Stopping {
		t.Fatalf("state = %s, want stopping", got)
	}
	release()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stopped analysis did not return")
	}
	stopped := s.Snapshot()
	if stopped.State != session.Stopped || stopped.FinishedAt == nil || stopped.Error != "" || s.Stop() {
		t.Fatalf("stopped snapshot = %+v", stopped)
	}
	if _, err := s.Run(context.Background(), &scriptedSource{}); !errors.Is(err, session.ErrAlreadyRun) {
		t.Errorf("repeated Run error = %v, want ErrAlreadyRun", err)
	}
}

type scriptedSource struct {
	packets []model.Packet
	err     error
	read    int
}

func (s *scriptedSource) Next() (model.Packet, error) {
	if s.read < len(s.packets) {
		p := s.packets[s.read]
		s.read++
		return p, nil
	}
	if s.err != nil {
		return model.Packet{}, s.err
	}
	return model.Packet{}, capture.ErrDone
}
func (s *scriptedSource) LinkType() string { return "Ethernet" }
func (s *scriptedSource) Stats() capture.Stats {
	var bytes uint64
	for _, p := range s.packets[:s.read] {
		bytes += uint64(p.WireLength)
	}
	return capture.Stats{Packets: uint64(s.read), Decoded: uint64(s.read), Bytes: bytes}
}
func (s *scriptedSource) Close() error { return nil }

func TestReadFailurePreservesErrorAndFinalCounters(t *testing.T) {
	wantErr := errors.New("capture device failed")
	src := &scriptedSource{
		packets: []model.Packet{{
			Timestamp: time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC),
			Src:       netip.MustParseAddr("10.0.0.42"), Dst: netip.MustParseAddr("198.51.100.1"),
			SrcPort: 50000, DstPort: 443, Proto: model.ProtoTCP, TCPFlags: model.TCPSyn, WireLength: 74,
		}},
		err: wantErr,
	}
	s := newSession(t)
	stats, err := s.Run(context.Background(), src)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Run error = %v, want underlying source error", err)
	}
	got := s.Snapshot()
	if got.State != session.Failed || !strings.Contains(got.Error, wantErr.Error()) || got.FinishedAt == nil {
		t.Fatalf("failed snapshot = %+v", got)
	}
	if got.Stats.Packets != 1 || got.Stats.Bytes != 74 || stats.Packets != got.Stats.Packets {
		t.Errorf("failure discarded final counters: %+v", got.Stats)
	}
}

func TestCancelledContextDoesNotReadCapture(t *testing.T) {
	s := newSession(t)
	src := &scriptedSource{packets: []model.Packet{{WireLength: 74}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Run(ctx, src); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if got := s.Snapshot(); got.State != session.Stopped || got.Stats.Packets != 0 || src.read != 0 {
		t.Fatalf("pre-cancelled run consumed input: %+v, reads %d", got, src.read)
	}
}

func TestNilSourceDoesNotConsumeSession(t *testing.T) {
	s := newSession(t)
	if _, err := s.Run(context.Background(), nil); err == nil {
		t.Fatal("nil source was accepted")
	}
	if s.Snapshot().State != session.Ready {
		t.Fatal("invalid request consumed the session")
	}
	if _, err := s.Run(context.Background(), &scriptedSource{}); err != nil {
		t.Fatal(err)
	}
	if got := s.Snapshot().State; got != session.Completed {
		t.Errorf("EOF state = %s, want completed", got)
	}
}

func TestNewRejectsInvalidRulesAndSpeed(t *testing.T) {
	for _, speed := range []float64{-1, math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := session.New(session.Options{Pipeline: pipeline.Options{Speed: speed}}, nil); err == nil {
			t.Errorf("accepted replay speed %v", speed)
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte("id: TH-0099\nname: broken\ndetector: absent\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := session.New(session.Options{RulesDir: dir}, nil); err == nil {
		t.Error("accepted invalid rule pack")
	}
}
