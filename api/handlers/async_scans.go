package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/ykbryan/domain-watcher/internal/store"
	"github.com/ykbryan/domain-watcher/internal/worker"
)

// AsyncScanStore is the scan_jobs surface the async handlers need. Distinct
// from the sync handler's ScanStore because it also needs CreateQueued + Get.
type AsyncScanStore interface {
	CreateQueued(ctx context.Context, target, triggeredBy string) (uuid.UUID, error)
	Get(ctx context.Context, id uuid.UUID) (*store.ScanJob, error)
}

// PermQueryStore is the read-side store surface for /results and /report.
type PermQueryStore interface {
	ListByScan(ctx context.Context, scanJobID uuid.UUID, opts store.ListOptions) ([]store.PermutationResult, int, error)
	CountByScan(ctx context.Context, scanJobID uuid.UUID) (total, live int, err error)
	BandCounts(ctx context.Context, scanJobID uuid.UUID) (store.BandCounts, error)
}

// FindingQueryStore queries aggregated finding info.
type FindingQueryStore interface {
	CountBySeverity(ctx context.Context, scanJobID uuid.UUID) (map[string]int, error)
}

// Enqueuer is the minimal interface a worker pool exposes to the handler.
type Enqueuer interface {
	Enqueue(scanID uuid.UUID) error
}

type AsyncScans struct {
	jobs     AsyncScanStore
	perms    PermQueryStore
	findings FindingQueryStore
	pool     Enqueuer
}

func NewAsyncScans(jobs AsyncScanStore, perms PermQueryStore, findings FindingQueryStore, pool Enqueuer) *AsyncScans {
	return &AsyncScans{jobs: jobs, perms: perms, findings: findings, pool: pool}
}

// --- POST /api/v1/scans ---

type asyncRequest struct {
	Domain  string `json:"domain"`
	Options struct {
		// Options are accepted but currently ignored (workers use server
		// defaults). Honored in S6+.
		MaxPermutations int `json:"max_permutations"`
	} `json:"options"`
}

type asyncCreateResponse struct {
	ScanID string `json:"scan_id"`
	Status string `json:"status"`
}

func (a *AsyncScans) Post(w http.ResponseWriter, r *http.Request) {
	var req asyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if domain == "" || !strings.Contains(domain, ".") {
		writeErr(w, http.StatusBadRequest, "domain required")
		return
	}

	scanID, err := a.jobs.CreateQueued(r.Context(), domain, store.TriggeredByAPI)
	if err != nil {
		slog.Error("async create queued failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "could not create scan")
		return
	}

	if err := a.pool.Enqueue(scanID); err != nil {
		if errors.Is(err, worker.ErrQueueFull) {
			writeErr(w, http.StatusServiceUnavailable, "scan queue full, try again shortly")
			return
		}
		writeErr(w, http.StatusInternalServerError, "enqueue failed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(asyncCreateResponse{ScanID: scanID.String(), Status: store.ScanStatusQueued})
}

// --- GET /api/v1/scans/{id} ---

type statusResponse struct {
	ScanID           string         `json:"scan_id"`
	TargetDomain     string         `json:"target_domain"`
	Status           string         `json:"status"`
	TriggeredBy      string         `json:"triggered_by"`
	CreatedAt        string         `json:"created_at"`
	CompletedAt      *string        `json:"completed_at,omitempty"`
	Error            *string        `json:"error,omitempty"`
	PermutationCount int            `json:"permutation_count"`
	LiveCount        int            `json:"live_count"`
	BandCounts       map[string]int `json:"band_counts"`
}

func (a *AsyncScans) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseScanID(w, r)
	if !ok {
		return
	}
	job, err := a.jobs.Get(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "scan not found")
		return
	}

	total, live, err := a.perms.CountByScan(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	bands, err := a.perms.BandCounts(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := statusResponse{
		ScanID:           job.ID.String(),
		TargetDomain:     job.TargetDomain,
		Status:           job.Status,
		TriggeredBy:      job.TriggeredBy,
		CreatedAt:        job.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		PermutationCount: total,
		LiveCount:        live,
		BandCounts:       bands,
	}
	if job.CompletedAt != nil {
		s := job.CompletedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.CompletedAt = &s
	}
	if job.Error != nil {
		resp.Error = job.Error
	}

	writeJSON(w, http.StatusOK, resp)
}

// --- GET /api/v1/scans/{id}/results ---

type resultsResponse struct {
	ScanID  string              `json:"scan_id"`
	Total   int                 `json:"total"`
	Limit   int                 `json:"limit"`
	Offset  int                 `json:"offset"`
	Results []resultRowResponse `json:"results"`
}

type resultRowResponse struct {
	Domain    string   `json:"domain"`
	A         []string `json:"a,omitempty"`
	MX        []string `json:"mx,omitempty"`
	NS        []string `json:"ns,omitempty"`
	IsLive    bool     `json:"is_live"`
	RiskScore *int     `json:"risk_score,omitempty"`
	RiskBand  *string  `json:"risk_band,omitempty"`
}

func (a *AsyncScans) GetResults(w http.ResponseWriter, r *http.Request) {
	id, ok := parseScanID(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	var bands []string
	if raw := q.Get("risk_band"); raw != "" {
		for _, b := range strings.Split(raw, ",") {
			if b = strings.TrimSpace(strings.ToUpper(b)); b != "" {
				bands = append(bands, b)
			}
		}
	}

	rows, total, err := a.perms.ListByScan(r.Context(), id, store.ListOptions{
		RiskBands: bands, Limit: limit, Offset: offset,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	out := resultsResponse{ScanID: id.String(), Total: total, Offset: offset, Limit: limit}
	if out.Limit == 0 {
		out.Limit = 50
	}
	out.Results = make([]resultRowResponse, 0, len(rows))
	for _, row := range rows {
		out.Results = append(out.Results, resultRowResponse{
			Domain: row.Domain, A: row.DNSA, MX: row.DNSMX, NS: row.DNSNS,
			IsLive: row.IsLive, RiskScore: row.RiskScore, RiskBand: row.RiskBand,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// --- GET /api/v1/scans/{id}/report ---

type reportResponse struct {
	ScanID             string              `json:"scan_id"`
	TargetDomain       string              `json:"target_domain"`
	Status             string              `json:"status"`
	PermutationCount   int                 `json:"permutation_count"`
	LiveCount          int                 `json:"live_count"`
	BandCounts         map[string]int      `json:"band_counts"`
	FindingsBySeverity map[string]int      `json:"findings_by_severity"`
	Top                []resultRowResponse `json:"top_domains"`
}

func (a *AsyncScans) GetReport(w http.ResponseWriter, r *http.Request) {
	id, ok := parseScanID(w, r)
	if !ok {
		return
	}
	job, err := a.jobs.Get(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "scan not found")
		return
	}
	total, live, err := a.perms.CountByScan(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	bands, err := a.perms.BandCounts(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	sev, err := a.findings.CountBySeverity(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	topRows, _, err := a.perms.ListByScan(r.Context(), id, store.ListOptions{Limit: 20})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	top := make([]resultRowResponse, 0, len(topRows))
	for _, row := range topRows {
		top = append(top, resultRowResponse{
			Domain: row.Domain, A: row.DNSA, MX: row.DNSMX, NS: row.DNSNS,
			IsLive: row.IsLive, RiskScore: row.RiskScore, RiskBand: row.RiskBand,
		})
	}

	writeJSON(w, http.StatusOK, reportResponse{
		ScanID:             job.ID.String(),
		TargetDomain:       job.TargetDomain,
		Status:             job.Status,
		PermutationCount:   total,
		LiveCount:          live,
		BandCounts:         bands,
		FindingsBySeverity: sev,
		Top:                top,
	})
}

func parseScanID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid scan id")
		return uuid.Nil, false
	}
	return id, true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
