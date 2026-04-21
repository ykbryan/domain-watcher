package monitor

import (
	"testing"

	"github.com/ykbryan/domain-watcher/internal/store"
)

func perm(domain, band string) store.PermutationResult {
	b := band
	return store.PermutationResult{Domain: domain, RiskBand: &b}
}

func permNil(domain string) store.PermutationResult {
	return store.PermutationResult{Domain: domain, RiskBand: nil}
}

func domains(results []store.PermutationResult) []string {
	out := make([]string, len(results))
	for i, r := range results {
		out[i] = r.Domain
	}
	return out
}

func TestDiff_NoBaseline_EmitsNothing(t *testing.T) {
	current := []store.PermutationResult{perm("a.com", "CRITICAL"), perm("b.com", "HIGH")}
	got := Diff(nil, current)
	if len(got) != 0 {
		t.Errorf("want no alerts on first scan, got %v", domains(got))
	}
}

func TestDiff_NewCriticalEmitted(t *testing.T) {
	prev := []store.PermutationResult{perm("stable.com", "CRITICAL")}
	curr := []store.PermutationResult{perm("stable.com", "CRITICAL"), perm("new.com", "CRITICAL")}
	got := Diff(prev, curr)
	if len(got) != 1 || got[0].Domain != "new.com" {
		t.Errorf("want [new.com], got %v", domains(got))
	}
}

func TestDiff_UpgradedBandEmitted(t *testing.T) {
	prev := []store.PermutationResult{perm("x.com", "LOW")}
	curr := []store.PermutationResult{perm("x.com", "HIGH")}
	got := Diff(prev, curr)
	if len(got) != 1 {
		t.Errorf("LOW→HIGH should emit; got %v", domains(got))
	}
}

func TestDiff_StableOrDowngradedNotEmitted(t *testing.T) {
	prev := []store.PermutationResult{perm("x.com", "CRITICAL"), perm("y.com", "HIGH")}
	curr := []store.PermutationResult{perm("x.com", "CRITICAL"), perm("y.com", "MEDIUM")}
	got := Diff(prev, curr)
	if len(got) != 0 {
		t.Errorf("stable/downgraded should not emit; got %v", domains(got))
	}
}

func TestDiff_CleanAndLowSkipped(t *testing.T) {
	prev := []store.PermutationResult{}
	curr := []store.PermutationResult{perm("c.com", "CLEAN"), perm("l.com", "LOW"), perm("m.com", "MEDIUM")}
	got := Diff(prev, curr)
	if len(got) != 0 {
		t.Errorf("only HIGH/CRITICAL should alert; got %v", domains(got))
	}
}

func TestDiff_NilBand(t *testing.T) {
	prev := []store.PermutationResult{permNil("p.com")}
	curr := []store.PermutationResult{permNil("p.com"), perm("h.com", "HIGH")}
	got := Diff(prev, curr)
	if len(got) != 1 || got[0].Domain != "h.com" {
		t.Errorf("nil band should be ignored, HIGH emitted; got %v", domains(got))
	}
}

func TestDiff_PreviouslyAbsent_NowHigh(t *testing.T) {
	// "Previously not present" is same as "previously not HIGH/CRITICAL" → emit.
	prev := []store.PermutationResult{perm("old.com", "CLEAN")}
	curr := []store.PermutationResult{perm("old.com", "CLEAN"), perm("fresh.com", "HIGH")}
	got := Diff(prev, curr)
	if len(got) != 1 || got[0].Domain != "fresh.com" {
		t.Errorf("want [fresh.com], got %v", domains(got))
	}
}
