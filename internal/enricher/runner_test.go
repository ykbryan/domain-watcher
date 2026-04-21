package enricher

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeSource struct {
	name   string
	signal RiskSignal
	err    error
	delay  time.Duration
}

func (f *fakeSource) Name() string { return f.name }
func (f *fakeSource) Enrich(ctx context.Context, domain string) (*Finding, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	return &Finding{SourceName: f.name, RiskSignals: []RiskSignal{f.signal}}, nil
}

func TestFanOut_SourcesPerDomain(t *testing.T) {
	srcs := []Source{
		&fakeSource{name: "a", signal: RiskSignal{Label: "sa", Severity: SeverityMedium}},
		&fakeSource{name: "b", signal: RiskSignal{Label: "sb", Severity: SeverityHigh}},
	}
	r := NewRunner(srcs, 4, 2*time.Second)
	out := r.FanOut(context.Background(), []string{"one.com", "two.com"})
	if len(out) != 2 {
		t.Fatalf("want 2 result rows, got %d", len(out))
	}
	for i, findings := range out {
		if len(findings) != 2 {
			t.Errorf("row %d: want 2 findings, got %d", i, len(findings))
		}
	}
}

func TestFanOut_ErrorRecordedNotPropagated(t *testing.T) {
	srcs := []Source{
		&fakeSource{name: "ok", signal: RiskSignal{Label: "l", Severity: SeverityLow}},
		&fakeSource{name: "broken", err: errors.New("api down")},
	}
	r := NewRunner(srcs, 2, 1*time.Second)
	out := r.FanOut(context.Background(), []string{"x.test"})
	if len(out[0]) != 2 {
		t.Fatalf("want 2 findings, got %d", len(out[0]))
	}
	var brokenFound bool
	for _, f := range out[0] {
		if f.SourceName == "broken" {
			brokenFound = true
			if f.Error != "api down" {
				t.Errorf("error not captured: %q", f.Error)
			}
			if f.FetchedAt.IsZero() {
				t.Errorf("fetched_at not backfilled on error")
			}
		}
	}
	if !brokenFound {
		t.Error("broken source finding not emitted")
	}
}

func TestFanOut_PerSourceTimeout(t *testing.T) {
	srcs := []Source{
		&fakeSource{name: "slow", delay: 500 * time.Millisecond},
	}
	r := NewRunner(srcs, 1, 100*time.Millisecond)
	out := r.FanOut(context.Background(), []string{"a"})
	if len(out[0]) != 1 || out[0][0].Error == "" {
		t.Errorf("expected timeout recorded as error, got %+v", out[0])
	}
}

func TestFanOut_EmptyInputs(t *testing.T) {
	r := NewRunner([]Source{&fakeSource{name: "a"}}, 1, time.Second)
	if got := r.FanOut(context.Background(), nil); len(got) != 0 {
		t.Errorf("expected empty slice, got %d", len(got))
	}
	r2 := NewRunner(nil, 1, time.Second)
	out := r2.FanOut(context.Background(), []string{"x"})
	if len(out) != 1 || len(out[0]) != 0 {
		t.Errorf("expected 1 empty row, got %+v", out)
	}
}
