package monitor

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/ykbryan/domain-watcher/internal/store"
)

// fakeMonitorStore tracks every lifecycle transition for assertions.
type fakeMonitorStore struct {
	mu            sync.Mutex
	dueForScan    []store.MonitoredDomain
	dueForDiff    []store.MonitoredDomain
	scanning      map[uuid.UUID]uuid.UUID // monitor id → scan id
	promoted      []uuid.UUID
}

func newFakeMonitorStore() *fakeMonitorStore {
	return &fakeMonitorStore{scanning: map[uuid.UUID]uuid.UUID{}}
}

func (f *fakeMonitorStore) DueForScan(context.Context) ([]store.MonitoredDomain, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]store.MonitoredDomain{}, f.dueForScan...)
	f.dueForScan = nil
	return out, nil
}
func (f *fakeMonitorStore) DueForDiff(context.Context) ([]store.MonitoredDomain, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]store.MonitoredDomain{}, f.dueForDiff...)
	f.dueForDiff = nil
	return out, nil
}
func (f *fakeMonitorStore) MarkScanning(_ context.Context, id, scanID uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scanning[id] = scanID
	return nil
}
func (f *fakeMonitorStore) PromoteScan(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.promoted = append(f.promoted, id)
	return nil
}

type fakeJobStore struct {
	mu      sync.Mutex
	created []string
}

func (f *fakeJobStore) CreateQueued(_ context.Context, target, _ string) (uuid.UUID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created = append(f.created, target)
	return uuid.New(), nil
}

type fakePermReader struct {
	mu   sync.Mutex
	data map[uuid.UUID][]store.PermutationResult
}

func (f *fakePermReader) ListByScan(_ context.Context, id uuid.UUID, _ store.ListOptions) ([]store.PermutationResult, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rows := f.data[id]
	return rows, len(rows), nil
}

type fakeAlertStore struct {
	mu   sync.Mutex
	rows []store.AlertRow
}

func (f *fakeAlertStore) Insert(_ context.Context, rows []store.AlertRow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows = append(f.rows, rows...)
	return nil
}

type fakeEnqueuer struct {
	mu      sync.Mutex
	queued  []uuid.UUID
	failNth int
	callN   int
}

func (f *fakeEnqueuer) Enqueue(id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callN++
	if f.failNth > 0 && f.callN == f.failNth {
		return errEnqueue
	}
	f.queued = append(f.queued, id)
	return nil
}

var errEnqueue = &fakeErr{"enqueue failed"}

type fakeErr struct{ s string }

func (e *fakeErr) Error() string { return e.s }

// ---

func TestScheduler_EnqueuesAndMarksScanning(t *testing.T) {
	m := newFakeMonitorStore()
	id := uuid.New()
	m.dueForScan = []store.MonitoredDomain{{ID: id, Domain: "example.com"}}
	j := &fakeJobStore{}
	s := New(Config{}, m, j, &fakePermReader{data: map[uuid.UUID][]store.PermutationResult{}}, &fakeAlertStore{}, &fakeEnqueuer{})

	s.Pass(context.Background())

	if len(j.created) != 1 || j.created[0] != "example.com" {
		t.Errorf("want scan created for example.com; got %v", j.created)
	}
	if _, ok := m.scanning[id]; !ok {
		t.Error("monitor should be marked scanning")
	}
}

func TestScheduler_EnqueueFailDoesNotMarkScanning(t *testing.T) {
	m := newFakeMonitorStore()
	id := uuid.New()
	m.dueForScan = []store.MonitoredDomain{{ID: id, Domain: "example.com"}}
	q := &fakeEnqueuer{failNth: 1}
	s := New(Config{}, m, &fakeJobStore{}, &fakePermReader{}, &fakeAlertStore{}, q)

	s.Pass(context.Background())
	if _, ok := m.scanning[id]; ok {
		t.Error("MarkScanning should not fire when Enqueue fails")
	}
}

func TestScheduler_DiffEmitsAlertsAndPromotes(t *testing.T) {
	mID := uuid.New()
	currScanID := uuid.New()
	lastScanID := uuid.New()

	m := newFakeMonitorStore()
	m.dueForDiff = []store.MonitoredDomain{
		{ID: mID, Domain: "example.com", CurrentScanID: &currScanID, LastScanID: &lastScanID},
	}
	critical := "CRITICAL"
	clean := "CLEAN"
	perms := &fakePermReader{data: map[uuid.UUID][]store.PermutationResult{
		lastScanID: {{Domain: "examp1e.com", RiskBand: &clean}},
		currScanID: {{Domain: "examp1e.com", RiskBand: &critical}, {Domain: "exxample.com", RiskBand: &critical}},
	}}
	alerts := &fakeAlertStore{}

	s := New(Config{}, m, &fakeJobStore{}, perms, alerts, &fakeEnqueuer{})
	s.Pass(context.Background())

	if len(alerts.rows) != 2 {
		t.Fatalf("want 2 alerts, got %d", len(alerts.rows))
	}
	if len(m.promoted) != 1 || m.promoted[0] != mID {
		t.Errorf("want monitor promoted; got %v", m.promoted)
	}
}

func TestScheduler_FirstScanNoAlerts(t *testing.T) {
	mID := uuid.New()
	currScanID := uuid.New()
	m := newFakeMonitorStore()
	m.dueForDiff = []store.MonitoredDomain{
		{ID: mID, Domain: "example.com", CurrentScanID: &currScanID, LastScanID: nil},
	}
	critical := "CRITICAL"
	perms := &fakePermReader{data: map[uuid.UUID][]store.PermutationResult{
		currScanID: {{Domain: "fresh.com", RiskBand: &critical}},
	}}
	alerts := &fakeAlertStore{}
	s := New(Config{}, m, &fakeJobStore{}, perms, alerts, &fakeEnqueuer{})
	s.Pass(context.Background())

	if len(alerts.rows) != 0 {
		t.Errorf("first-scan baseline should emit no alerts; got %d", len(alerts.rows))
	}
	if len(m.promoted) != 1 {
		t.Errorf("monitor should still be promoted after first scan; got %v", m.promoted)
	}
}
