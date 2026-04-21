package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTelegram_NilWithoutToken(t *testing.T) {
	if s := NewTelegram(""); s != nil {
		t.Error("expected nil when token is empty")
	}
}

func TestTelegram_EnabledRequiresChatID(t *testing.T) {
	tg := NewTelegram("token")
	if tg.Enabled(Target{}) {
		t.Error("Enabled should be false without chat_id")
	}
	if !tg.Enabled(Target{TelegramChatID: "-100123"}) {
		t.Error("Enabled should be true with chat_id")
	}
}

func TestTelegram_MessageBody(t *testing.T) {
	b := sampleBatch(2)
	text := buildTelegramText(b)
	if !strings.Contains(text, "*Domain Threat Alert:") {
		t.Errorf("missing header: %q", text)
	}
	if !strings.Contains(text, "2 new threats detected") {
		t.Errorf("missing count: %q", text)
	}
	if !strings.Contains(text, "CRITICAL") {
		t.Errorf("missing band: %q", text)
	}
}

func TestTelegram_Truncation(t *testing.T) {
	b := sampleBatch(15)
	text := buildTelegramText(b)
	if !strings.Contains(text, "…and 5 more") {
		t.Errorf("expected truncation, got: %q", text)
	}
}

func TestTelegram_Send_PostsToBotAPI(t *testing.T) {
	var got telegramRequest
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tg := NewTelegramWithBase(srv.URL, "secret-token")
	err := tg.Send(context.Background(), sampleBatch(2), Target{TelegramChatID: "-100999"})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotPath != "/botsecret-token/sendMessage" {
		t.Errorf("path: %q", gotPath)
	}
	if got.ChatID != "-100999" {
		t.Errorf("chat_id: %q", got.ChatID)
	}
	if got.ParseMode != "Markdown" {
		t.Errorf("parse_mode: %q", got.ParseMode)
	}
	if !strings.Contains(got.Text, "Domain Threat Alert") {
		t.Errorf("text missing header: %q", got.Text)
	}
}

func TestTelegram_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	tg := NewTelegramWithBase(srv.URL, "token")
	err := tg.Send(context.Background(), sampleBatch(1), Target{TelegramChatID: "1"})
	if err == nil {
		t.Error("expected error on 403")
	}
}

func TestTelegram_MarkdownEscape(t *testing.T) {
	// If target_domain itself contains markdown chars, escape them.
	b := sampleBatch(1)
	b.TargetDomain = "e*xample_.com"
	text := buildTelegramText(b)
	if strings.Contains(text, "e*xample_.com") {
		t.Errorf("unescaped markdown chars in header: %q", text)
	}
}
