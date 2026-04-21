package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"

	"github.com/ykbryan/domain-watcher/internal/resolver"
	"github.com/ykbryan/domain-watcher/internal/store"
)

// fakeScanStore implements ScanStore, PermStore, and FindingStore with an
// in-memory log so handler tests don't need a real Postgres.
type fakeScanStore struct {
	mu        sync.Mutex
	created   []string
	completed []uuid.UUID
	failed    map[uuid.UUID]string
	rows      map[uuid.UUID][]store.PermutationRow
	findings  []store.FindingRow
}

func newFakeStore() *fakeScanStore {
	return &fakeScanStore{
		failed: map[uuid.UUID]string{},
		rows:   map[uuid.UUID][]store.PermutationRow{},
	}
}

func (f *fakeScanStore) Create(_ context.Context, target, _ string) (uuid.UUID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created = append(f.created, target)
	return uuid.New(), nil
}
func (f *fakeScanStore) MarkCompleted(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.completed = append(f.completed, id)
	return nil
}
func (f *fakeScanStore) MarkFailed(_ context.Context, id uuid.UUID, msg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed[id] = msg
	return nil
}
func (f *fakeScanStore) BulkInsert(_ context.Context, id uuid.UUID, rows []store.PermutationRow) ([]uuid.UUID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows[id] = append(f.rows[id], rows...)
	ids := make([]uuid.UUID, len(rows))
	for i := range ids {
		ids[i] = uuid.New()
	}
	return ids, nil
}

// fakeFindingStore implements FindingStore. Kept separate because both stores
// carry a method named BulkInsert with different signatures.
type fakeFindingStore struct {
	mu      sync.Mutex
	parent  *fakeScanStore
}

func (f *fakeFindingStore) BulkInsert(_ context.Context, rows []store.FindingRow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.parent.mu.Lock()
	f.parent.findings = append(f.parent.findings, rows...)
	f.parent.mu.Unlock()
	return nil
}

// mockDNS spins up a UDP DNS server that answers A queries with 203.0.113.9
// for every domain whose second-level label starts with "live". Anything
// else returns NXDOMAIN.
func mockDNS(t *testing.T) (addr string, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		for _, q := range req.Question {
			name := q.Name
			if q.Qtype == dns.TypeA && len(name) > 4 && name[:4] == "live" {
				rr, _ := dns.NewRR(name + " 60 IN A 203.0.113.9")
				m.Answer = append(m.Answer, rr)
			}
		}
		if len(m.Answer) == 0 {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	return pc.LocalAddr().String(), func() { _ = srv.Shutdown() }
}

func TestPostQuick_Success(t *testing.T) {
	addr, stop := mockDNS(t)
	defer stop()

	fake := newFakeStore()
	h := NewScans(fake, fake, &fakeFindingStore{parent: fake}, ScansConfig{
		QuickMaxPerms: 50,
		QuickTimeout:  5 * time.Second,
		TopN:          5,
		Resolver:      resolver.Config{Upstreams: []string{addr}, Workers: 10, Timeout: 1 * time.Second},
	})

	body, _ := json.Marshal(quickRequest{Domain: "live.test"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans/quick", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.PostQuick(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d — body: %s", rec.Code, rec.Body.String())
	}
	var resp quickResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ScanID == "" {
		t.Error("scan_id empty")
	}
	if resp.TargetDomain != "live.test" {
		t.Errorf("target_domain: %q", resp.TargetDomain)
	}
	if resp.PermutationCount == 0 {
		t.Error("permutation_count zero")
	}
	// mockDNS only marks domains starting with "live" as live — most perms will be NXDOMAIN.
	// But our input "live.test" will produce some perms still starting with "live" (e.g. "live.test" homoglyphs).
	// At minimum, no crash, response shape correct, store invoked.
	if len(fake.created) != 1 {
		t.Errorf("want 1 create call, got %d", len(fake.created))
	}
	if len(fake.completed) != 1 {
		t.Errorf("want 1 complete call, got %d", len(fake.completed))
	}
	if len(fake.rows) != 1 {
		t.Errorf("want 1 scan's rows inserted, got %d", len(fake.rows))
	}
	for _, rows := range fake.rows {
		if len(rows) != resp.PermutationCount {
			t.Errorf("row count %d != permutation_count %d", len(rows), resp.PermutationCount)
		}
	}
}

func TestPostQuick_InvalidDomain(t *testing.T) {
	fake := newFakeStore()
	h := NewScans(fake, fake, &fakeFindingStore{parent: fake}, ScansConfig{})

	for _, body := range []string{`{}`, `{"domain":""}`, `{"domain":"no-dot"}`, `not-json`} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/scans/quick", bytes.NewReader([]byte(body)))
		rec := httptest.NewRecorder()
		h.PostQuick(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: want 400, got %d", body, rec.Code)
		}
	}
	if len(fake.created) != 0 {
		t.Errorf("no scan should be created on bad request; got %d", len(fake.created))
	}
}

// errStore fails on Create so the handler's error path is exercised.
type errStore struct{ fakeScanStore }

func (e *errStore) Create(_ context.Context, _, _ string) (uuid.UUID, error) {
	return uuid.Nil, errors.New("db down")
}

func TestPostQuick_StoreFailure(t *testing.T) {
	e := &errStore{fakeScanStore: *newFakeStore()}
	h := NewScans(e, &e.fakeScanStore, &fakeFindingStore{parent: &e.fakeScanStore}, ScansConfig{})
	body, _ := json.Marshal(quickRequest{Domain: "example.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans/quick", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.PostQuick(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d", rec.Code)
	}
}
