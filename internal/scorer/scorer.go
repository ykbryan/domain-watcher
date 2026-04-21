// Package scorer turns a bag of enricher RiskSignals into a 0–100 score and
// a severity band, applying the multipliers from the spec.
package scorer

import (
	"math"

	"github.com/ykbryan/domain-watcher/internal/enricher"
)

type Band string

const (
	BandClean    Band = "CLEAN"
	BandLow      Band = "LOW"
	BandMedium   Band = "MEDIUM"
	BandHigh     Band = "HIGH"
	BandCritical Band = "CRITICAL"
)

// Severity weights per spec.
const (
	weightCritical = 40
	weightHigh     = 15
	weightMedium   = 5
	weightInfo     = 1

	multMXPresent          = 1.5 // MX record → can receive email → BEC risk
	multFreshCertAndLive   = 1.3 // cert issued <24h AND DNS live → brand new attack
	multVTMalAndURLhausOn  = 1.5 // VT malicious>0 AND URLhaus online (S6 adds VT)
)

// Inputs captures the non-signal context a domain's scoring depends on.
type Inputs struct {
	Findings []enricher.Finding
	HasMX    bool
	IsLive   bool
}

// Score computes {score, band} for one domain's findings.
// Returns (0, CLEAN) when there are no signals.
func Score(in Inputs) (int, Band) {
	var raw float64
	var signalCount int

	// Flags used by multipliers
	var certFreshUnder24h, urlhausOnline, vtMalicious bool

	for _, f := range in.Findings {
		for _, s := range f.RiskSignals {
			signalCount++
			raw += severityWeight(s.Severity)
			switch s.Label {
			case "cert_issued_under_24h":
				certFreshUnder24h = true
			case "urlhaus_online":
				urlhausOnline = true
			case "virustotal_malicious":
				vtMalicious = true
			}
		}
	}

	if signalCount == 0 {
		return 0, BandClean
	}

	if in.HasMX {
		raw *= multMXPresent
	}
	if certFreshUnder24h && in.IsLive {
		raw *= multFreshCertAndLive
	}
	if vtMalicious && urlhausOnline {
		raw *= multVTMalAndURLhausOn
	}

	score := int(math.Round(raw))
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return score, bandFor(score)
}

func severityWeight(s enricher.Severity) float64 {
	switch s {
	case enricher.SeverityCritical:
		return weightCritical
	case enricher.SeverityHigh:
		return weightHigh
	case enricher.SeverityMedium:
		return weightMedium
	case enricher.SeverityInfo, enricher.SeverityLow:
		return weightInfo
	}
	return 0
}

// BandFor returns the band a raw 0–100 score falls into. Exposed so
// aggregate scores (e.g. per-scan maximum) can be labeled without
// re-running Score.
func BandFor(score int) Band { return bandFor(score) }

func bandFor(score int) Band {
	switch {
	case score <= 10:
		return BandClean
	case score <= 25:
		return BandLow
	case score <= 50:
		return BandMedium
	case score <= 75:
		return BandHigh
	default:
		return BandCritical
	}
}
