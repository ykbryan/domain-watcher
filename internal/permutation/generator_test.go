package permutation

import (
	"context"
	"strings"
	"testing"
)

func TestGenerate_ProducesManyPermutations(t *testing.T) {
	perms, err := Generate(context.Background(), "example.com", Options{IncludeDictionary: true})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(perms) < 100 {
		t.Errorf("want > 100 permutations, got %d", len(perms))
	}
}

func TestGenerate_ContainsKnownLookalike(t *testing.T) {
	perms, err := Generate(context.Background(), "example.com", Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// 'l' → '1' is in the Homoglyph map; expect examp1e.com in output.
	if !contains(perms, "examp1e.com") {
		t.Errorf("expected examp1e.com in permutations; got %d perms, sample: %v", len(perms), sample(perms, 10))
	}
}

func TestGenerate_NoDuplicates(t *testing.T) {
	perms, err := Generate(context.Background(), "example.com", Options{IncludeDictionary: true})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	seen := make(map[string]struct{}, len(perms))
	for _, p := range perms {
		if _, dup := seen[p]; dup {
			t.Errorf("duplicate permutation: %q", p)
		}
		seen[p] = struct{}{}
	}
}

func TestGenerate_ExcludesOriginal(t *testing.T) {
	perms, err := Generate(context.Background(), "example.com", Options{IncludeDictionary: true})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if contains(perms, "example.com") {
		t.Errorf("original domain should be excluded from permutations")
	}
}

func TestGenerate_RespectsMax(t *testing.T) {
	perms, err := Generate(context.Background(), "example.com", Options{Max: 50, IncludeDictionary: true})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(perms) != 50 {
		t.Errorf("want 50 permutations (cap), got %d", len(perms))
	}
}

func TestGenerate_DictionaryApplied(t *testing.T) {
	with, err := Generate(context.Background(), "example.com", Options{IncludeDictionary: true})
	if err != nil {
		t.Fatalf("Generate(with): %v", err)
	}
	// Suffix and word-subdomain forms are dictionary-only contributions.
	// (login-example.com is produced by the library's Prefix strategy regardless.)
	if !contains(with, "example-verify.com") {
		t.Errorf("expected example-verify.com (suffix form) with dictionary enabled")
	}
	if !contains(with, "exampleverify.com") {
		t.Errorf("expected exampleverify.com (suffix form) with dictionary enabled")
	}
	if !contains(with, "verify.example.com") {
		t.Errorf("expected verify.example.com (word subdomain) with dictionary enabled")
	}

	without, err := Generate(context.Background(), "example.com", Options{IncludeDictionary: false})
	if err != nil {
		t.Fatalf("Generate(without): %v", err)
	}
	if contains(without, "example-verify.com") {
		t.Errorf("dictionary suffix patterns should not appear when IncludeDictionary=false")
	}
}

func TestGenerate_EmptyDomain(t *testing.T) {
	if _, err := Generate(context.Background(), "", Options{}); err == nil {
		t.Error("expected error for empty domain")
	}
}

func TestGenerate_Deterministic(t *testing.T) {
	a, _ := Generate(context.Background(), "example.com", Options{IncludeDictionary: true})
	b, _ := Generate(context.Background(), "example.com", Options{IncludeDictionary: true})
	if len(a) != len(b) {
		t.Fatalf("non-deterministic length: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("non-deterministic at %d: %q vs %q", i, a[i], b[i])
			return
		}
	}
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func sample(ss []string, n int) []string {
	out := make([]string, 0, n)
	for _, s := range ss {
		if strings.HasPrefix(s, "examp") {
			out = append(out, s)
			if len(out) >= n {
				break
			}
		}
	}
	return out
}
