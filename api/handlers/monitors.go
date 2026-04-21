package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/ykbryan/domain-watcher/internal/store"
)

// MonitorStore is the write/read surface for monitored_domains CRUD.
type MonitorStore interface {
	Create(ctx context.Context, domain string, ownerEmail string, alertChannels json.RawMessage, intervalMinutes int) (uuid.UUID, error)
	Delete(ctx context.Context, id uuid.UUID) error
	Get(ctx context.Context, id uuid.UUID) (*store.MonitoredDomain, error)
	List(ctx context.Context) ([]store.MonitoredDomain, error)
}

type AlertReader interface {
	ListByMonitor(ctx context.Context, monitorID uuid.UUID, limit int) ([]store.Alert, error)
}

type Monitors struct {
	store  MonitorStore
	alerts AlertReader
}

func NewMonitors(s MonitorStore, alerts AlertReader) *Monitors {
	return &Monitors{store: s, alerts: alerts}
}

type monitorRequest struct {
	Domain               string          `json:"domain"`
	OwnerEmail           string          `json:"owner_email"`
	CheckIntervalHours   int             `json:"check_interval_hours"`
	CheckIntervalMinutes int             `json:"check_interval_minutes"` // preferred over hours when > 0
	AlertChannels        json.RawMessage `json:"alert_channels"`
}

type monitorDTO struct {
	ID                   string          `json:"id"`
	Domain               string          `json:"domain"`
	OwnerEmail           *string         `json:"owner_email,omitempty"`
	CheckIntervalMinutes int             `json:"check_interval_minutes"`
	AlertChannels        json.RawMessage `json:"alert_channels"`
	LastCheckedAt        *string         `json:"last_checked_at,omitempty"`
	CreatedAt            string          `json:"created_at"`
}

func toDTO(m store.MonitoredDomain) monitorDTO {
	dto := monitorDTO{
		ID:                   m.ID.String(),
		Domain:               m.Domain,
		OwnerEmail:           m.OwnerEmail,
		CheckIntervalMinutes: m.CheckIntervalMinutes,
		AlertChannels:        m.AlertChannels,
		CreatedAt:            m.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	if m.LastCheckedAt != nil {
		s := m.LastCheckedAt.Format("2006-01-02T15:04:05Z07:00")
		dto.LastCheckedAt = &s
	}
	return dto
}

// POST /api/v1/monitors
func (m *Monitors) Post(w http.ResponseWriter, r *http.Request) {
	var req monitorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if domain == "" || !strings.Contains(domain, ".") {
		writeErr(w, http.StatusBadRequest, "domain required")
		return
	}
	// Spec body uses hours; accept minutes too (tests + high-frequency use).
	intervalMinutes := req.CheckIntervalMinutes
	if intervalMinutes <= 0 {
		intervalMinutes = req.CheckIntervalHours * 60
	}
	if intervalMinutes <= 0 {
		intervalMinutes = 24 * 60 // default 24h
	}
	id, err := m.store.Create(r.Context(), domain, strings.TrimSpace(req.OwnerEmail), req.AlertChannels, intervalMinutes)
	if err != nil {
		slog.Error("monitor create failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "create failed")
		return
	}
	md, err := m.store.Get(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, toDTO(*md))
}

// GET /api/v1/monitors
func (m *Monitors) List(w http.ResponseWriter, r *http.Request) {
	mds, err := m.store.List(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]monitorDTO, 0, len(mds))
	for _, md := range mds {
		out = append(out, toDTO(md))
	}
	writeJSON(w, http.StatusOK, map[string]any{"monitors": out})
}

// DELETE /api/v1/monitors/{id}
func (m *Monitors) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := m.store.Delete(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /api/v1/monitors/{id}/alerts
func (m *Monitors) ListAlerts(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	alerts, err := m.alerts.ListByMonitor(r.Context(), id, 100)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	type alertDTO struct {
		ID                string          `json:"id"`
		PermutationDomain string          `json:"permutation_domain"`
		RiskScore         int             `json:"risk_score"`
		RiskBand          string          `json:"risk_band"`
		FindingsSummary   json.RawMessage `json:"findings_summary"`
		CreatedAt         string          `json:"created_at"`
		SentAt            *string         `json:"sent_at,omitempty"`
	}
	out := make([]alertDTO, 0, len(alerts))
	for _, a := range alerts {
		dto := alertDTO{
			ID:                a.ID.String(),
			PermutationDomain: a.PermutationDomain,
			RiskScore:         a.RiskScore,
			RiskBand:          a.RiskBand,
			FindingsSummary:   a.FindingsSummary,
			CreatedAt:         a.AlertCreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
		if a.AlertSentAt != nil {
			s := a.AlertSentAt.Format("2006-01-02T15:04:05Z07:00")
			dto.SentAt = &s
		}
		out = append(out, dto)
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": out})
}
