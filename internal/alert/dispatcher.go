package alert

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
)

// Dispatcher fans a Batch out to every registered Channel that is
// Enabled for the Target. Channels run in parallel; one failure does
// not stop the others.
type Dispatcher struct {
	channels []Channel
}

func NewDispatcher(channels ...Channel) *Dispatcher {
	// Drop nils so callers can pass conditional constructors inline.
	clean := make([]Channel, 0, len(channels))
	for _, c := range channels {
		if !isNil(c) {
			clean = append(clean, c)
		}
	}
	return &Dispatcher{channels: clean}
}

// Channels returns the names of registered channels (for startup logging).
func (d *Dispatcher) Channels() []string {
	out := make([]string, 0, len(d.channels))
	for _, c := range d.channels {
		out = append(out, c.Name())
	}
	return out
}

// Result captures per-channel outcome for a single Dispatch call.
type Result struct {
	Channel string
	Err     error // nil = success; sentinel ErrSkipped = channel disabled for target
}

// ErrSkipped marks a channel that wasn't applicable for a target.
var ErrSkipped = fmt.Errorf("skipped")

// Dispatch runs all enabled channels in parallel. Always returns len==len(channels)
// results in registration order.
func (d *Dispatcher) Dispatch(ctx context.Context, batch Batch, target Target) []Result {
	results := make([]Result, len(d.channels))
	var wg sync.WaitGroup
	for i, c := range d.channels {
		results[i].Channel = c.Name()
		if !c.Enabled(target) {
			results[i].Err = ErrSkipped
			continue
		}
		wg.Add(1)
		go func(idx int, ch Channel) {
			defer wg.Done()
			if err := ch.Send(ctx, batch, target); err != nil {
				slog.Warn("alert channel send failed", "channel", ch.Name(), "monitor", batch.MonitorID, "err", err)
				results[idx].Err = err
			}
		}(i, c)
	}
	wg.Wait()
	return results
}

// isNil handles the typed-nil-interface pitfall: interface wrapping a
// nil *Source still compares != nil.
func isNil(c Channel) bool {
	if c == nil {
		return true
	}
	switch v := c.(type) {
	case *Telegram:
		return v == nil
	case *Email:
		return v == nil
	case *Lark:
		return v == nil
	}
	return false
}

// AnySuccess returns true if at least one non-skipped channel succeeded.
// Scheduler uses this to decide whether to MarkSent.
func AnySuccess(results []Result) bool {
	for _, r := range results {
		if r.Err == nil {
			return true
		}
	}
	return false
}
