package worker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ykbryan/domain-watcher/internal/pipeline"
	"github.com/ykbryan/domain-watcher/internal/store"
)

// fakeJobStore records calls and returns a canned job for Get.
type fakeJobStore struct {
	mu        sync.Mutex
	jobs      map[uuid.UUID]*store.ScanJob
	running   []uuid.UUID
	completed []uuid.UUID
	failed    map[uuid.UUID]string
	getErr    error
}

func newFakeJobs() *fakeJobStore {
	return &fakeJobStore{
		jobs:   map[uuid.UUID]*store.ScanJob{},
		failed: map[uuid.UUID]string{},
	}
}
func (f *fakeJobStore) Add(j *store.ScanJob) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jobs[j.ID] = j
}
func (f *fakeJobStore) MarkRunning(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.running = append(f.running, id)
	if j, ok := f.jobs[id]; ok {
		j.Status = store.ScanStatusRunning
	}
	return nil
}
func (f *fakeJobStore) MarkCompleted(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.completed = append(f.completed, id)
	return nil
}
func (f *fakeJobStore) MarkFailed(_ context.Context, id uuid.UUID, msg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed[id] = msg
	return nil
}
func (f *fakeJobStore) Get(_ context.Context, id uuid.UUID) (*store.ScanJob, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.jobs[id], nil
}

// noopPermStore / noopFindingStore satisfy pipeline's store interfaces.
// pipeline.Run is heavy (network DNS + enrichment), so these tests use
// an invalid resolver config to short-circuit — we only care about
// worker lifecycle and error handling here.
type noopPermStore struct{}

func (noopPermStore) BulkInsert(context.Context, uuid.UUID, []store.PermutationRow) ([]uuid.UUID, error) {
	return nil, nil
}
func (noopPermStore) UpdateScores(context.Context, []store.ScoreUpdate) error { return nil }

type noopFindingStore struct{}

func (noopFindingStore) BulkInsert(context.Context, []store.FindingRow) error { return nil }

func TestPool_EnqueueAndProcess(t *testing.T) {
	jobs := newFakeJobs()
	id := uuid.New()
	jobs.Add(&store.ScanJob{ID: id, TargetDomain: "example.com", Status: store.ScanStatusQueued})

	// Empty Sources + MaxPerms=1 keeps the pipeline fast (no enrichment).
	// Resolver timeout=100ms so DNS doesn't stall the test.
	p := New(Config{Workers: 1, QueueSize: 4, JobBudget: 2 * time.Second},
		jobs, noopPermStore{}, noopFindingStore{},
		pipeline.Options{MaxPerms: 1, IncludeDictionary: false})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)

	if err := p.Enqueue(id); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Give worker time to pick up and complete.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := p.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	jobs.mu.Lock()
	defer jobs.mu.Unlock()
	if len(jobs.running) != 1 {
		t.Errorf("want 1 MarkRunning call, got %d", len(jobs.running))
	}
	// Either Completed or Failed — both are fine for this test; we just want
	// confirmation the worker ran the job to a terminal state.
	if len(jobs.completed)+len(jobs.failed) != 1 {
		t.Errorf("want 1 terminal mark, got %d completed + %d failed", len(jobs.completed), len(jobs.failed))
	}
}

func TestPool_QueueFull(t *testing.T) {
	jobs := newFakeJobs()
	// Queue size 1, no workers started → second enqueue fails.
	p := New(Config{Workers: 0, QueueSize: 1}, jobs, noopPermStore{}, noopFindingStore{}, pipeline.Options{})
	if err := p.Enqueue(uuid.New()); err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	if err := p.Enqueue(uuid.New()); !errors.Is(err, ErrQueueFull) {
		t.Errorf("second enqueue want ErrQueueFull, got %v", err)
	}
}

func TestPool_SkipTerminalJob(t *testing.T) {
	jobs := newFakeJobs()
	id := uuid.New()
	jobs.Add(&store.ScanJob{ID: id, TargetDomain: "example.com", Status: store.ScanStatusCompleted})

	p := New(Config{Workers: 1, QueueSize: 1}, jobs, noopPermStore{}, noopFindingStore{}, pipeline.Options{MaxPerms: 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)

	if err := p.Enqueue(id); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	_ = p.Shutdown(shutdownCtx)

	jobs.mu.Lock()
	defer jobs.mu.Unlock()
	if len(jobs.running) != 0 {
		t.Errorf("terminal job should be skipped, MarkRunning called %d times", len(jobs.running))
	}
}
