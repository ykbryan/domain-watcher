package permutation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/weppos/publicsuffix-go/publicsuffix"
	"zntr.io/typogenerator"
	"zntr.io/typogenerator/mapping"
	"zntr.io/typogenerator/strategy"
)

// Options controls generation behavior.
type Options struct {
	// Max caps the number of returned permutations. 0 = unlimited.
	Max int
	// IncludeDictionary toggles brand-impersonation prepend/append patterns
	// (login-example.com, example-verify.com, secure.example.com, ...).
	IncludeDictionary bool
}

var allStrategies = []strategy.Strategy{
	strategy.Omission,
	strategy.Repetition,
	strategy.Transposition,
	strategy.Replace(mapping.English),
	strategy.Addition,
	strategy.BitSquatting,
	strategy.Homoglyph,
	strategy.Hyphenation,
	strategy.VowelSwap,
	strategy.SubDomain,
	strategy.Similar(mapping.English),
	strategy.Prefix,
	strategy.DoubleHit(mapping.English),
	strategy.TLDRepeat,
	strategy.TLDReplace,
}

// dictionaryWords are common phishing-adjacent tokens per the spec.
var dictionaryWords = []string{
	"login", "secure", "auth", "portal", "payment", "verify",
	"account", "support", "help", "update", "my", "online",
	"official", "www", "mail", "banking",
}

// Generate returns deduplicated typosquat/lookalike permutations for domain.
// The original domain is never included. Results are sorted for determinism.
func Generate(ctx context.Context, domain string, opts Options) ([]string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, errors.New("empty domain")
	}

	parsed, err := publicsuffix.Parse(domain)
	if err != nil {
		return nil, fmt.Errorf("parse domain: %w", err)
	}

	results, err := typogenerator.FuzzDomain(domain, allStrategies...)
	if err != nil {
		return nil, fmt.Errorf("fuzz: %w", err)
	}

	set := make(map[string]struct{}, 2048)
	for _, r := range results {
		for _, p := range r.Permutations {
			set[p] = struct{}{}
		}
	}

	if opts.IncludeDictionary {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		applyDictionary(set, parsed.SLD, parsed.TLD)
	}

	delete(set, domain)

	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	sort.Strings(out)

	if opts.Max > 0 && len(out) > opts.Max {
		out = out[:opts.Max]
	}

	return out, nil
}

func applyDictionary(set map[string]struct{}, sld, tld string) {
	for _, word := range dictionaryWords {
		set[fmt.Sprintf("%s-%s.%s", word, sld, tld)] = struct{}{}
		set[fmt.Sprintf("%s%s.%s", word, sld, tld)] = struct{}{}
		set[fmt.Sprintf("%s-%s.%s", sld, word, tld)] = struct{}{}
		set[fmt.Sprintf("%s%s.%s", sld, word, tld)] = struct{}{}
		set[fmt.Sprintf("%s.%s.%s", word, sld, tld)] = struct{}{}
	}
}
