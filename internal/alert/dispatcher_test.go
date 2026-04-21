package alert

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

// fakeChannel records invocations and returns a canned error.
type fakeChannel struct {
	name    string
	enabled bool
	err     error
	calls   atomic.Int32
}

func (f *fakeChannel) Name() string        { return f.name }
func (f *fakeChannel) Enabled(Target) bool { return f.enabled }
func (f *fakeChannel) Send(context.Context, Batch, Target) error {
	f.calls.Add(1)
	return f.err
}

func TestDispatcher_CallsEnabledOnly(t *testing.T) {
	a := &fakeChannel{name: "a", enabled: true}
	b := &fakeChannel{name: "b", enabled: false}
	d := NewDispatcher(a, b)

	res := d.Dispatch(context.Background(), Batch{MonitorID: uuid.New()}, Target{})
	if len(res) != 2 {
		t.Fatalf("want 2 results, got %d", len(res))
	}
	if res[0].Err != nil {
		t.Errorf("a should succeed: %v", res[0].Err)
	}
	if !errors.Is(res[1].Err, ErrSkipped) {
		t.Errorf("b should be skipped: %v", res[1].Err)
	}
	if a.calls.Load() != 1 {
		t.Errorf("a calls: %d", a.calls.Load())
	}
	if b.calls.Load() != 0 {
		t.Errorf("disabled channel should not be called: %d", b.calls.Load())
	}
}

func TestDispatcher_OneFailureDoesNotBlockOthers(t *testing.T) {
	ok := &fakeChannel{name: "ok", enabled: true}
	broken := &fakeChannel{name: "broken", enabled: true, err: errors.New("boom")}
	d := NewDispatcher(ok, broken)

	res := d.Dispatch(context.Background(), Batch{}, Target{})
	if ok.calls.Load() != 1 || broken.calls.Load() != 1 {
		t.Errorf("both channels should have been called: ok=%d, broken=%d", ok.calls.Load(), broken.calls.Load())
	}
	if res[0].Err != nil {
		t.Errorf("ok should succeed: %v", res[0].Err)
	}
	if res[1].Err == nil {
		t.Error("broken should return its error")
	}
	if !AnySuccess(res) {
		t.Error("AnySuccess should report true when any channel succeeded")
	}
}

func TestDispatcher_AllFail(t *testing.T) {
	a := &fakeChannel{name: "a", enabled: true, err: errors.New("x")}
	b := &fakeChannel{name: "b", enabled: true, err: errors.New("y")}
	d := NewDispatcher(a, b)
	res := d.Dispatch(context.Background(), Batch{}, Target{})
	if AnySuccess(res) {
		t.Error("AnySuccess should be false when all fail")
	}
}

func TestDispatcher_DropsNilChannels(t *testing.T) {
	// NewTelegram("") returns nil; make sure Dispatcher survives that.
	d := NewDispatcher(NewTelegram(""), NewEmail(SMTPConfig{}), &fakeChannel{name: "real", enabled: true})
	if names := d.Channels(); len(names) != 1 || names[0] != "real" {
		t.Errorf("nil channels should be dropped; got %v", names)
	}
}

func TestDispatcher_EmptyChannels(t *testing.T) {
	d := NewDispatcher()
	res := d.Dispatch(context.Background(), Batch{}, Target{})
	if len(res) != 0 {
		t.Errorf("no channels => no results, got %d", len(res))
	}
}
