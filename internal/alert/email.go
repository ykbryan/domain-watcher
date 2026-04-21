package alert

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"net/smtp"
	"strings"
)

// SMTPConfig is the global SMTP setup read from env at startup.
type SMTPConfig struct {
	Host string
	Port string
	User string
	Pass string
	From string
}

// Email sends an HTML message via net/smtp.SendMail. Per-monitor recipient
// is the monitor's owner_email; Target.Email must be true to enable.
type Email struct {
	cfg    SMTPConfig
	sendFn func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

// NewEmail returns nil when SMTP is not configured (host or from missing).
func NewEmail(cfg SMTPConfig) *Email {
	if cfg.Host == "" || cfg.From == "" {
		return nil
	}
	return &Email{cfg: cfg, sendFn: smtp.SendMail}
}

func (e *Email) Name() string { return "email" }

func (e *Email) Enabled(t Target) bool {
	return t.Email && strings.Contains(t.OwnerEmail, "@")
}

func (e *Email) Send(_ context.Context, b Batch, t Target) error {
	subject, body, err := buildEmailMessage(b)
	if err != nil {
		return fmt.Errorf("build: %w", err)
	}
	msg := formatSMTPMessage(e.cfg.From, t.OwnerEmail, subject, body)
	addr := e.cfg.Host + ":" + e.cfg.Port
	var auth smtp.Auth
	if e.cfg.User != "" {
		auth = smtp.PlainAuth("", e.cfg.User, e.cfg.Pass, e.cfg.Host)
	}
	if err := e.sendFn(addr, auth, e.cfg.From, []string{t.OwnerEmail}, []byte(msg)); err != nil {
		return fmt.Errorf("smtp send: %w", err)
	}
	return nil
}

// ---

const emailHTMLTemplate = `<!DOCTYPE html>
<html><body style="font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif; color:#1a1a1a; max-width:640px; margin:0 auto; padding:24px;">
<h2 style="color:#b00020; margin:0 0 8px 0;">Domain Threat Alert: {{.TargetDomain}}</h2>
<p style="margin:0 0 16px 0; color:#444;"><strong>{{.Count}} new threat{{if ne .Count 1}}s{{end}} detected</strong> during the latest scan of {{.TargetDomain}}.</p>
<table cellspacing="0" cellpadding="8" border="0" style="border-collapse:collapse; border:1px solid #e3e3e3; width:100%;">
<thead><tr style="background:#f5f5f7;"><th align="left">Domain</th><th align="left">Band</th><th align="right">Score</th></tr></thead>
<tbody>
{{range .Items}}<tr style="border-top:1px solid #e3e3e3;"><td>{{.Domain}}</td><td>{{.RiskBand}}</td><td align="right">{{.RiskScore}}</td></tr>{{end}}
</tbody>
</table>
<p style="margin-top:16px; color:#777; font-size:12px;">Scan ID: {{.ScanID}}</p>
</body></html>`

type emailData struct {
	TargetDomain string
	Count        int
	Items        []Item
	ScanID       string
}

func buildEmailMessage(b Batch) (subject, body string, err error) {
	subject = fmt.Sprintf("Domain Threat Alert: %s (%d new)", b.TargetDomain, len(b.Items))
	tmpl, err := template.New("alert").Parse(emailHTMLTemplate)
	if err != nil {
		return "", "", err
	}
	var buf bytes.Buffer
	data := emailData{
		TargetDomain: b.TargetDomain,
		Count:        len(b.Items),
		Items:        b.Items,
		ScanID:       b.ScanID.String(),
	}
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", "", err
	}
	return subject, buf.String(), nil
}

// formatSMTPMessage assembles RFC 5322 headers + HTML body.
func formatSMTPMessage(from, to, subject, htmlBody string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "From: %s\r\n", from)
	fmt.Fprintf(&sb, "To: %s\r\n", to)
	fmt.Fprintf(&sb, "Subject: %s\r\n", subject)
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/html; charset=\"utf-8\"\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(htmlBody)
	return sb.String()
}
