// Package session builds and runs one analysis independently of the CLI or GUI.
package session

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/baldoseri/tracehound/internal/capture"
	"github.com/baldoseri/tracehound/internal/detect"
	"github.com/baldoseri/tracehound/internal/model"
	"github.com/baldoseri/tracehound/internal/pipeline"
	"github.com/baldoseri/tracehound/internal/rules"
)

// State describes the lifecycle of an analysis, independently of whether its
// dashboard or event stream is connected.
type State string

const (
	Ready     State = "ready"
	Running   State = "running"
	Stopping  State = "stopping"
	Completed State = "completed"
	Stopped   State = "stopped"
	Failed    State = "failed"
)

// ErrAlreadyRun prevents reusing detector history and pipeline counters for a
// second capture. Create a new Session for each analysis.
var ErrAlreadyRun = errors.New("session: analysis has already started")

// Options configures the same backend for terminal and graphical clients.
type Options struct {
	RulesDir      string
	HomeNets      []netip.Prefix
	AlertCooldown time.Duration
	Pipeline      pipeline.Options
}

// RuleSummary describes the rule pack selected for this analysis.
type RuleSummary struct {
	Origin  string `json:"origin"`
	Total   int    `json:"total"`
	Enabled int    `json:"enabled"`
}

// Snapshot is safe to read during analysis. Error is populated for failed runs;
// cancellation is represented by Stopped and still returned to the Run caller.
type Snapshot struct {
	State      State          `json:"state"`
	StartedAt  *time.Time     `json:"started_at,omitempty"`
	FinishedAt *time.Time     `json:"finished_at,omitempty"`
	Error      string         `json:"error,omitempty"`
	Stats      pipeline.Stats `json:"stats"`
	Rules      RuleSummary    `json:"rules"`
}

// Session owns one engine, inventory, and pipeline. Run is synchronous: callers
// that need a responsive GUI can run it on a worker goroutine and call Stop and
// Snapshot concurrently. Alert sinks execute on the analysis goroutine and must
// return promptly. Source ownership stays with the caller, which must Close it
// after Run returns.
type Session struct {
	pipe *pipeline.Pipeline
	eng  *detect.Engine
	inv  *detect.Inventory
	pack RuleSummary

	mu         sync.Mutex
	state      State
	startedAt  time.Time
	finishedAt time.Time
	failure    string
	cancel     context.CancelFunc
}

// New loads and validates rules before any analysis starts. A nil sink discards
// alerts, allowing a caller to inspect configuration without an output target.
func New(opts Options, sink func(model.Alert)) (*Session, error) {
	if opts.Pipeline.Speed < 0 || math.IsNaN(opts.Pipeline.Speed) || math.IsInf(opts.Pipeline.Speed, 0) {
		return nil, errors.New("session: replay speed must be finite and non-negative")
	}
	pack, err := rules.Load(opts.RulesDir)
	if err != nil {
		return nil, err
	}
	detectors, inventory, err := pack.Detectors()
	if err != nil {
		return nil, err
	}
	if sink == nil {
		sink = func(model.Alert) {}
	}
	cfg := detect.Config{
		HomeNets:      slices.Clone(opts.HomeNets),
		AlertCooldown: opts.AlertCooldown,
		Policy:        pack.Policy(),
	}
	engine := detect.NewEngine(cfg, sink)
	for _, d := range detectors {
		engine.Register(d)
	}
	opts.Pipeline.Detect = cfg
	return &Session{
		pipe:  pipeline.New(engine, opts.Pipeline),
		eng:   engine,
		inv:   inventory,
		pack:  RuleSummary{Origin: pack.Origin, Total: pack.Len(), Enabled: pack.Enabled()},
		state: Ready,
	}, nil
}

// Pipeline, Engine, and Inventory expose the analysis to read-only adapters such
// as the HTTP API. Lifecycle operations must go through Session.Run and Stop.
func (s *Session) Pipeline() *pipeline.Pipeline { return s.pipe }
func (s *Session) Engine() *detect.Engine       { return s.eng }
func (s *Session) Inventory() *detect.Inventory { return s.inv }
func (s *Session) Rules() RuleSummary           { return s.pack }

// Run consumes src once and records the outcome. It rejects concurrent or
// repeated runs, so a new capture never inherits a previous capture's evidence.
func (s *Session) Run(ctx context.Context, src capture.Source) (pipeline.Stats, error) {
	if src == nil {
		return pipeline.Stats{}, errors.New("session: capture source is required")
	}
	s.mu.Lock()
	if s.state != Ready {
		s.mu.Unlock()
		return pipeline.Stats{}, ErrAlreadyRun
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.state = Running
	s.startedAt = time.Now().UTC()
	s.mu.Unlock()
	defer cancel()

	stats, err := s.pipe.Run(runCtx, src)
	s.mu.Lock()
	s.cancel = nil
	s.finishedAt = time.Now().UTC()
	switch {
	case err == nil:
		s.state = Completed
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		s.state = Stopped
	default:
		s.state = Failed
		s.failure = err.Error()
	}
	s.mu.Unlock()
	return stats, err
}

// Stop requests cancellation without waiting for the analysis goroutine. It is
// idempotent while stopping and returns false when there is no active analysis.
func (s *Session) Stop() bool {
	s.mu.Lock()
	if s.state != Running && s.state != Stopping {
		s.mu.Unlock()
		return false
	}
	s.state = Stopping
	cancel := s.cancel
	s.mu.Unlock()
	cancel()
	return true
}

// Snapshot returns lifecycle metadata and the pipeline's concurrent counters.
// Timestamps are copies, so callers cannot mutate the session through them.
func (s *Session) Snapshot() Snapshot {
	s.mu.Lock()
	out := Snapshot{State: s.state, Error: s.failure, Rules: s.pack}
	if !s.startedAt.IsZero() {
		started := s.startedAt
		out.StartedAt = &started
	}
	if !s.finishedAt.IsZero() {
		finished := s.finishedAt
		out.FinishedAt = &finished
	}
	s.mu.Unlock()
	out.Stats = s.pipe.Stats()
	return out
}
