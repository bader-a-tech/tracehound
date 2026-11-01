package pipeline_test

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/baldoseri/tracehound/internal/capture"
	"github.com/baldoseri/tracehound/internal/detect"
	"github.com/baldoseri/tracehound/internal/model"
	"github.com/baldoseri/tracehound/internal/pipeline"
)

// silentSource models the case the periodic cancellation check cannot handle:
// a live interface carrying no traffic, where Next blocks in a read that has no
// deadline and no packet is coming to release it.
//
// A real LiveSource is Linux-only and needs CAP_NET_RAW, so it cannot be opened
// from a test. What can be tested is the contract the pipeline relies on, which
// is where the bug was: the loop never asked the source to stop.
type silentSource struct {
	entered    chan struct{} // closed once Next is blocking, so no test sleeps
	release    chan struct{}
	once       sync.Once
	interrupts atomic.Int64
}

func newSilentSource() *silentSource {
	return &silentSource{entered: make(chan struct{}), release: make(chan struct{})}
}

func (s *silentSource) Next() (model.Packet, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return model.Packet{}, capture.ErrDone
}

func (s *silentSource) LinkType() string     { return "Ethernet" }
func (s *silentSource) Stats() capture.Stats { return capture.Stats{} }
func (s *silentSource) Close() error         { return nil }

func (s *silentSource) Interrupt() error {
	if s.interrupts.Add(1) == 1 {
		close(s.release)
	}
	return nil
}

// TestRunReturnsWhenASilentSourceIsCancelled is the regression test for a sniff
// that could not be stopped.
//
// Cancellation used to be visible only at a counter boundary inside the loop,
// and the loop could not reach that check because it was parked in the read. On
// a quiet link the process had to be killed, which loses the run summary and
// the device inventory, since both happen after Run returns.
func TestRunReturnsWhenASilentSourceIsCancelled(t *testing.T) {
	engine := detect.NewEngine(detect.Config{}, func(model.Alert) {})
	p := pipeline.New(engine, pipeline.Options{TickInterval: time.Second})
	src := newSilentSource()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := p.Run(ctx, src)
		done <- err
	}()

	// Wait until the read is genuinely blocked, so the test cannot pass by
	// cancelling before Run ever called Next.
	<-src.entered
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run error = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancellation; a silent link still hangs the sensor")
	}

	if got := src.interrupts.Load(); got == 0 {
		t.Error("the source was never interrupted, so it returned for some other reason")
	}
}

// spacedSource has a capture-time gap that must never become an
// uninterruptible wall-clock sleep during paced replay.
type spacedSource struct {
	read       int
	secondRead chan struct{}
	start      time.Time
}

func (s *spacedSource) Next() (model.Packet, error) {
	if s.read == 2 {
		return model.Packet{}, capture.ErrDone
	}
	at := s.start.Add(time.Duration(s.read) * time.Hour)
	s.read++
	if s.read == 2 {
		close(s.secondRead)
	}
	return model.Packet{
		Timestamp:  at,
		Src:        netip.MustParseAddr("10.0.0.1"),
		Dst:        netip.MustParseAddr("192.0.2.1"),
		SrcPort:    51000,
		DstPort:    443,
		Proto:      model.ProtoTCP,
		WireLength: 74,
	}, nil
}

func (s *spacedSource) LinkType() string { return "Ethernet" }
func (s *spacedSource) Stats() capture.Stats {
	return capture.Stats{Packets: uint64(s.read)}
}
func (s *spacedSource) Close() error { return nil }

func TestPacedReplayStopsDuringACaptureTimeGap(t *testing.T) {
	engine := detect.NewEngine(detect.Config{}, func(model.Alert) {})
	p := pipeline.New(engine, pipeline.Options{Speed: 1})
	src := &spacedSource{
		secondRead: make(chan struct{}),
		start:      time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		stats pipeline.Stats
		err   error
	}
	done := make(chan result, 1)
	go func() {
		stats, err := p.Run(ctx, src)
		done <- result{stats, err}
	}()

	// Only cancel after the first packet has been analysed and the packet
	// after the one-hour gap has been read. The old implementation then
	// slept for an hour, even though the context had been cancelled.
	select {
	case <-src.secondRead:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not reach the capture-time gap")
	}
	cancel()
	select {
	case got := <-done:
		if !errors.Is(got.err, context.Canceled) {
			t.Errorf("Run error = %v, want context.Canceled", got.err)
		}
		if got.stats.Packets != 1 {
			t.Errorf("analysed %d packets, want only the first packet", got.stats.Packets)
		}
		if !got.stats.LastPacket.Equal(src.start) {
			t.Errorf("last analysed packet = %s, want %s", got.stats.LastPacket, src.start)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("paced replay did not stop during a capture-time gap")
	}
}

// TestRunDoesNotInterruptASourceThatFinishes guards the other direction: the
// watcher must not fire on the ordinary path, or every completed replay would
// be closing its own source out from under itself.
func TestRunDoesNotInterruptASourceThatFinishes(t *testing.T) {
	engine := detect.NewEngine(detect.Config{}, func(model.Alert) {})
	p := pipeline.New(engine, pipeline.Options{TickInterval: time.Second})

	src := newSilentSource()
	close(src.release) // Next returns ErrDone immediately

	if _, err := p.Run(context.Background(), src); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Give the watcher goroutine a chance to misbehave before asserting.
	time.Sleep(50 * time.Millisecond)

	if got := src.interrupts.Load(); got != 0 {
		t.Errorf("source was interrupted %d times on a clean finish, want 0", got)
	}
}
