package scorer

import (
	"testing"

	"github.com/ykbryan/domain-watcher/internal/enricher"
)

func f(signals ...enricher.RiskSignal) enricher.Finding {
	return enricher.Finding{SourceName: "t", RiskSignals: signals}
}

func sig(label string, sev enricher.Severity) enricher.RiskSignal {
	return enricher.RiskSignal{Label: label, Severity: sev}
}

func TestScore_CleanNoSignals(t *testing.T) {
	score, band := Score(Inputs{})
	if score != 0 || band != BandClean {
		t.Errorf("expected (0, CLEAN); got (%d, %s)", score, band)
	}
}

func TestScore_TableDriven(t *testing.T) {
	cases := []struct {
		name     string
		in       Inputs
		wantScore int
		wantBand Band
	}{
		{
			name:     "one INFO -> CLEAN",
			in:       Inputs{Findings: []enricher.Finding{f(sig("info", enricher.SeverityInfo))}},
			wantScore: 1,
			wantBand: BandClean,
		},
		{
			name:     "one MEDIUM -> CLEAN (5 ≤ 10)",
			in:       Inputs{Findings: []enricher.Finding{f(sig("m", enricher.SeverityMedium))}},
			wantScore: 5,
			wantBand: BandClean,
		},
		{
			name:     "one HIGH -> LOW (15 in 11-25)",
			in:       Inputs{Findings: []enricher.Finding{f(sig("h", enricher.SeverityHigh))}},
			wantScore: 15,
			wantBand: BandLow,
		},
		{
			name:     "one CRITICAL -> MEDIUM (40)",
			in:       Inputs{Findings: []enricher.Finding{f(sig("c", enricher.SeverityCritical))}},
			wantScore: 40,
			wantBand: BandMedium,
		},
		{
			name: "two CRITICAL -> 80 CRITICAL",
			in: Inputs{Findings: []enricher.Finding{
				f(sig("c1", enricher.SeverityCritical), sig("c2", enricher.SeverityCritical)),
			}},
			wantScore: 80,
			wantBand: BandCritical,
		},
		{
			name: "HIGH + MX multiplier -> 15*1.5=22.5 -> 23 LOW (still ≤25)",
			in: Inputs{
				Findings: []enricher.Finding{f(sig("h", enricher.SeverityHigh))},
				HasMX:    true,
			},
			wantScore: 23,
			wantBand: BandLow,
		},
		{
			name: "CRITICAL + MX multiplier -> 60 HIGH",
			in: Inputs{
				Findings: []enricher.Finding{f(sig("c", enricher.SeverityCritical))},
				HasMX:    true,
			},
			wantScore: 60,
			wantBand: BandHigh,
		},
		{
			name: "fresh cert <24h + live + MX stacks multipliers",
			// raw = 40 (CRITICAL) * 1.5 (MX) * 1.3 (fresh cert + live) = 78
			in: Inputs{
				Findings: []enricher.Finding{f(sig("cert_issued_under_24h", enricher.SeverityCritical))},
				HasMX:    true,
				IsLive:   true,
			},
			wantScore: 78,
			wantBand: BandCritical,
		},
		{
			name: "fresh cert <24h but NOT live -> multiplier does not apply",
			in: Inputs{
				Findings: []enricher.Finding{f(sig("cert_issued_under_24h", enricher.SeverityCritical))},
				IsLive:   false,
			},
			wantScore: 40,
			wantBand: BandMedium,
		},
		{
			name: "sum capped at 100",
			in: Inputs{Findings: []enricher.Finding{f(
				sig("c1", enricher.SeverityCritical),
				sig("c2", enricher.SeverityCritical),
				sig("c3", enricher.SeverityCritical),
				sig("c4", enricher.SeverityCritical),
			)}},
			wantScore: 100,
			wantBand: BandCritical,
		},
		{
			name: "VT malicious + URLhaus online stacks multiplier (S6 signal labels)",
			// 40 (CRITICAL VT) + 40 (CRITICAL URLhaus) = 80, * 1.5 = 120 capped to 100
			in: Inputs{Findings: []enricher.Finding{f(
				sig("virustotal_malicious", enricher.SeverityCritical),
				sig("urlhaus_online", enricher.SeverityCritical),
			)}},
			wantScore: 100,
			wantBand: BandCritical,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			score, band := Score(tc.in)
			if score != tc.wantScore || band != tc.wantBand {
				t.Errorf("got (%d, %s); want (%d, %s)", score, band, tc.wantScore, tc.wantBand)
			}
		})
	}
}

func TestBandFor_Boundaries(t *testing.T) {
	cases := []struct {
		score int
		want  Band
	}{
		{0, BandClean},
		{10, BandClean},
		{11, BandLow},
		{25, BandLow},
		{26, BandMedium},
		{50, BandMedium},
		{51, BandHigh},
		{75, BandHigh},
		{76, BandCritical},
		{100, BandCritical},
	}
	for _, c := range cases {
		if got := bandFor(c.score); got != c.want {
			t.Errorf("bandFor(%d) = %s; want %s", c.score, got, c.want)
		}
	}
}
