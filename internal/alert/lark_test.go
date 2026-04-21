package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func sampleBatch(n int) Batch {
	items := make([]Item, n)
	for i := 0; i < n; i++ {
		items[i] = Item{
			Domain:    "x" + string(rune('a'+i)) + ".example",
			RiskScore: 80 - i,
			RiskBand:  "CRITICAL",
		}
	}
	return Batch{
		MonitorID:    uuid.New(),
		TargetDomain: "example.com",
		ScanID:       uuid.New(),
		Items:        items,
	}
}

func TestLark_EnabledRequiresWebhook(t *testing.T) {
	l := NewLark()
	if l.Enabled(Target{}) {
		t.Error("Enabled should be false without a webhook")
	}
	if !l.Enabled(Target{LarkWebhook: "https://open.larksuite.com/webhook/xyz"}) {
		t.Error("Enabled should be true with a webhook")
	}
}

func TestLark_CardShape(t *testing.T) {
	b := sampleBatch(3)
	card := buildLarkCard(b)
	if card["msg_type"] != "interactive" {
		t.Errorf("msg_type: %v", card["msg_type"])
	}
	inner, ok := card["card"].(map[string]any)
	if !ok {
		t.Fatal("card missing")
	}
	header, ok := inner["header"].(map[string]any)
	if !ok {
		t.Fatal("header missing")
	}
	title := header["title"].(map[string]any)["content"].(string)
	if !strings.Contains(title, "example.com") {
		t.Errorf("title should contain target domain: %q", title)
	}
	if header["template"] != "red" {
		t.Errorf("template: %v", header["template"])
	}
	elements := inner["elements"].([]any)
	if len(elements) < 3 {
		t.Errorf("want >=3 elements, got %d", len(elements))
	}
}

func TestLark_TruncatesAtMax(t *testing.T) {
	b := sampleBatch(15)
	card := buildLarkCard(b)
	elements := card["card"].(map[string]any)["elements"].([]any)
	// Find the bullets element (3rd after summary + hr).
	bullets := elements[2].(map[string]any)["text"].(map[string]any)["content"].(string)
	if !strings.Contains(bullets, "…and 5 more") {
		t.Errorf("expected truncation notice; got: %q", bullets)
	}
}

func TestLark_Send_PostsToWebhook(t *testing.T) {
	var received map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content-type: %q", r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	l := NewLark()
	err := l.Send(context.Background(), sampleBatch(2), Target{LarkWebhook: srv.URL})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if received["msg_type"] != "interactive" {
		t.Errorf("webhook received wrong payload shape: %v", received)
	}
}

func TestLark_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	l := NewLark()
	err := l.Send(context.Background(), sampleBatch(1), Target{LarkWebhook: srv.URL})
	if err == nil {
		t.Error("expected error on 502")
	}
}
