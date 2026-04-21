// Package monitor implements the scheduler that drives monitored_domains
// re-scans and the differ that decides which permutations warrant an alert.
package monitor

import (
	"github.com/ykbryan/domain-watcher/internal/store"
)

// Diff returns the set of current permutations whose risk_band became
// HIGH or CRITICAL since the previous scan — i.e. they either weren't
// HIGH/CRITICAL in previous or didn't exist there at all.
//
// A nil previous slice means there was no baseline (the monitor's first
// scan); by design Diff returns nothing in that case to avoid an initial
// alert storm.
func Diff(previous, current []store.PermutationResult) []store.PermutationResult {
	if previous == nil {
		return nil
	}
	prevBands := make(map[string]string, len(previous))
	for _, p := range previous {
		if p.RiskBand != nil {
			prevBands[p.Domain] = *p.RiskBand
		}
	}
	var out []store.PermutationResult
	for _, c := range current {
		if c.RiskBand == nil {
			continue
		}
		band := *c.RiskBand
		if !isAlertable(band) {
			continue
		}
		if was, ok := prevBands[c.Domain]; !ok || !isAlertable(was) {
			out = append(out, c)
		}
	}
	return out
}

func isAlertable(band string) bool {
	return band == "HIGH" || band == "CRITICAL"
}
