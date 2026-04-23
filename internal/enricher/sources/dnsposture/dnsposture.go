// Package dnsposture inspects the email-related DNS posture of a
// domain — MX, SPF, DMARC — to surface signals the resolver layer
// doesn't track. No external API; uses Go's net.Resolver.
//
// A typosquat configured to send mail (MX present) but without SPF
// or DMARC is a strong indicator of brand-impersonation email
// campaigns. The multiplier rule "MX record present × 1.5" already
// exists in the methodology; this source lets the scorer make finer
// distinctions within the MX-present cohort.
package dnsposture

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ykbryan/domain-watcher/internal/enricher"
)

const (
	sourceName   = "dnsposture"
	lookupBudget = 3 * time.Second
)

type Source struct {
	resolver *net.Resolver
}

// New always returns a configured Source. Callers can safely include
// it unconditionally — there are no credentials to miss.
func New() *Source {
	return &Source{resolver: net.DefaultResolver}
}

func (s *Source) Name() string { return sourceName }

func (s *Source) Enrich(ctx context.Context, domain string) (*enricher.Finding, error) {
	ctx, cancel := context.WithTimeout(ctx, lookupBudget)
	defer cancel()

	mxs, _ := s.resolver.LookupMX(ctx, domain)
	hasMX := len(mxs) > 0

	// SPF lives as a TXT record on the apex.
	var spf string
	if txts, err := s.resolver.LookupTXT(ctx, domain); err == nil {
		for _, t := range txts {
			if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
				spf = t
				break
			}
		}
	}

	// DMARC is a TXT at _dmarc.<domain>.
	var dmarc string
	if txts, err := s.resolver.LookupTXT(ctx, "_dmarc."+domain); err == nil {
		for _, t := range txts {
			if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
				dmarc = t
				break
			}
		}
	}

	f := &enricher.Finding{
		SourceName: sourceName,
		RawData: map[string]any{
			"mx_present":  hasMX,
			"spf_present": spf != "",
			"dmarc_raw":   dmarc,
		},
	}

	// The phishing-risk ladder:
	// - MX present, no SPF, no DMARC       -> high (classic impersonation setup)
	// - MX present, SPF but no DMARC       -> medium
	// - MX present, DMARC p=none           -> medium (monitoring only)
	// - MX present, DMARC p=quarantine/reject -> info (reasonable posture)
	switch {
	case hasMX && spf == "" && dmarc == "":
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "dns_posture_mail_no_policy",
			Severity: enricher.SeverityHigh,
			Detail:   "MX configured but no SPF or DMARC record",
		})
	case hasMX && spf == "" && dmarc != "":
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "dns_posture_mail_no_spf",
			Severity: enricher.SeverityMedium,
			Detail:   "MX configured, DMARC present, but no SPF",
		})
	case hasMX && spf != "" && dmarc == "":
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "dns_posture_mail_no_dmarc",
			Severity: enricher.SeverityMedium,
			Detail:   "MX + SPF configured but no DMARC policy",
		})
	case hasMX && dmarc != "":
		p := dmarcPolicy(dmarc)
		switch p {
		case "none":
			f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
				Label:    "dns_posture_dmarc_monitor_only",
				Severity: enricher.SeverityMedium,
				Detail:   "DMARC p=none: monitor-only, no enforcement",
			})
		case "quarantine", "reject":
			f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
				Label:    "dns_posture_dmarc_enforcing",
				Severity: enricher.SeverityInfo,
				Detail:   fmt.Sprintf("DMARC p=%s (enforcing)", p),
			})
		}
	case !hasMX:
		// No mail posture to reason about. Intentionally silent; the
		// absence of MX is already available to the scorer from the
		// resolver layer.
	}

	return f, nil
}

// dmarcPolicy extracts the p= directive from a DMARC TXT record.
// Returns "" if unparseable.
func dmarcPolicy(record string) string {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(strings.ToLower(part))
		if strings.HasPrefix(part, "p=") {
			v := strings.TrimPrefix(part, "p=")
			// Only the three defined values are meaningful.
			switch v {
			case "none", "quarantine", "reject":
				return v
			}
		}
	}
	return ""
}
