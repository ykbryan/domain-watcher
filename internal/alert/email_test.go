package alert

import (
	"context"
	"errors"
	"net/smtp"
	"strings"
	"sync"
	"testing"
)

func TestEmail_NilWithoutSMTP(t *testing.T) {
	if e := NewEmail(SMTPConfig{}); e != nil {
		t.Error("expected nil without host")
	}
	if e := NewEmail(SMTPConfig{Host: "smtp.test"}); e != nil {
		t.Error("expected nil without From")
	}
}

func TestEmail_Enabled(t *testing.T) {
	e := NewEmail(SMTPConfig{Host: "smtp.test", From: "a@b"})
	if e.Enabled(Target{Email: false, OwnerEmail: "u@x.com"}) {
		t.Error("Enabled should be false when target.Email=false")
	}
	if e.Enabled(Target{Email: true, OwnerEmail: ""}) {
		t.Error("Enabled should be false without owner_email")
	}
	if !e.Enabled(Target{Email: true, OwnerEmail: "u@x.com"}) {
		t.Error("Enabled should be true with email+owner")
	}
}

func TestEmail_SubjectAndBody(t *testing.T) {
	b := sampleBatch(3)
	subject, body, err := buildEmailMessage(b)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.Contains(subject, "3 new") {
		t.Errorf("subject missing count: %q", subject)
	}
	if !strings.Contains(subject, "example.com") {
		t.Errorf("subject missing domain: %q", subject)
	}
	if !strings.Contains(body, "<html>") {
		t.Errorf("body missing html tag")
	}
	if !strings.Contains(body, "Domain Threat Alert") {
		t.Errorf("body missing header: %q", body)
	}
	for _, it := range b.Items {
		if !strings.Contains(body, it.Domain) {
			t.Errorf("body missing item domain %q", it.Domain)
		}
	}
}

func TestEmail_SubjectSingular(t *testing.T) {
	b := sampleBatch(1)
	subject, _, _ := buildEmailMessage(b)
	if !strings.Contains(subject, "1 new") {
		t.Errorf("singular subject: %q", subject)
	}
}

func TestEmail_SMTPHeaders(t *testing.T) {
	msg := formatSMTPMessage("from@test", "to@test", "hello", "<p>hi</p>")
	for _, want := range []string{"From: from@test", "To: to@test", "Subject: hello", "MIME-Version: 1.0", "Content-Type: text/html"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in message", want)
		}
	}
}

func TestEmail_Send_InvokesSendFn(t *testing.T) {
	var mu sync.Mutex
	var gotAddr, gotFrom string
	var gotTo []string
	var gotMsg []byte

	e := &Email{
		cfg: SMTPConfig{Host: "smtp.test", Port: "587", User: "u", Pass: "p", From: "from@test"},
		sendFn: func(addr string, _ smtp.Auth, from string, to []string, msg []byte) error {
			mu.Lock()
			defer mu.Unlock()
			gotAddr, gotFrom, gotTo, gotMsg = addr, from, to, msg
			return nil
		},
	}
	err := e.Send(context.Background(), sampleBatch(1), Target{Email: true, OwnerEmail: "user@x.com"})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotAddr != "smtp.test:587" {
		t.Errorf("addr: %q", gotAddr)
	}
	if gotFrom != "from@test" {
		t.Errorf("from: %q", gotFrom)
	}
	if len(gotTo) != 1 || gotTo[0] != "user@x.com" {
		t.Errorf("to: %v", gotTo)
	}
	if !strings.Contains(string(gotMsg), "Domain Threat Alert") {
		t.Errorf("msg body missing header")
	}
}

func TestEmail_Send_WrapsError(t *testing.T) {
	e := &Email{
		cfg:    SMTPConfig{Host: "smtp.test", Port: "25", From: "from@test"},
		sendFn: func(string, smtp.Auth, string, []string, []byte) error { return errors.New("auth failed") },
	}
	err := e.Send(context.Background(), sampleBatch(1), Target{Email: true, OwnerEmail: "u@x"})
	if err == nil || !strings.Contains(err.Error(), "auth failed") {
		t.Errorf("want wrapped smtp error, got %v", err)
	}
}
