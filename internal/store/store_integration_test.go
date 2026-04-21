package store

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
)

// storeTestPool returns a pool connected to TEST_DATABASE_URL, or skips if unset.
// Tests using this helper are integration tests — run with:
//
//	TEST_DATABASE_URL=postgres://... go test ./internal/store/...
func storeTestPool(t *testing.T) (context.Context, *pooledDeps) {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx := context.Background()
	if err := Migrate(dbURL); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := NewPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	// Clean slate: truncate in FK-safe order.
	if _, err := pool.Exec(ctx, "TRUNCATE TABLE permutations, scan_jobs RESTART IDENTITY CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return ctx, &pooledDeps{
		jobs:  NewScanJobs(pool),
		perms: NewPermutations(pool),
	}
}

type pooledDeps struct {
	jobs  *ScanJobs
	perms *Permutations
}

func TestScanJobLifecycle(t *testing.T) {
	ctx, d := storeTestPool(t)

	id, err := d.jobs.Create(ctx, "example.com", TriggeredByAPI)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if id == uuid.Nil {
		t.Fatal("got nil uuid")
	}

	job, err := d.jobs.Get(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if job.Status != ScanStatusRunning || job.TargetDomain != "example.com" {
		t.Errorf("unexpected state: %+v", job)
	}

	if err := d.jobs.MarkCompleted(ctx, id); err != nil {
		t.Fatalf("mark completed: %v", err)
	}
	job, _ = d.jobs.Get(ctx, id)
	if job.Status != ScanStatusCompleted || job.CompletedAt == nil {
		t.Errorf("not marked completed: %+v", job)
	}
}

func TestPermutationBulkInsertAndCount(t *testing.T) {
	ctx, d := storeTestPool(t)
	id, _ := d.jobs.Create(ctx, "example.com", TriggeredByAPI)

	rows := []PermutationRow{
		{Domain: "examp1e.com", DNSA: []string{"1.2.3.4"}, DNSMX: nil, DNSNS: []string{"ns.x"}, IsLive: true},
		{Domain: "exampel.com", DNSA: nil, DNSMX: nil, DNSNS: nil, IsLive: false},
		{Domain: "xample.com", DNSA: []string{"5.6.7.8"}, DNSMX: []string{"aspmx.l.google.com."}, DNSNS: nil, IsLive: true},
	}
	if err := d.perms.BulkInsert(ctx, id, rows); err != nil {
		t.Fatalf("bulk insert: %v", err)
	}
	total, live, err := d.perms.CountByScan(ctx, id)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if total != 3 || live != 2 {
		t.Errorf("counts wrong: total=%d live=%d", total, live)
	}
}
