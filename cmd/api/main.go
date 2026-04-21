package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"

	"github.com/ykbryan/domain-watcher/api/handlers"
	"github.com/ykbryan/domain-watcher/internal/enricher"
	"github.com/ykbryan/domain-watcher/internal/enricher/sources/abusech"
	"github.com/ykbryan/domain-watcher/internal/enricher/sources/abuseipdb"
	"github.com/ykbryan/domain-watcher/internal/enricher/sources/certwatch"
	"github.com/ykbryan/domain-watcher/internal/enricher/sources/ipinfo"
	"github.com/ykbryan/domain-watcher/internal/enricher/sources/openphish"
	"github.com/ykbryan/domain-watcher/internal/enricher/sources/otx"
	"github.com/ykbryan/domain-watcher/internal/enricher/sources/rdap"
	"github.com/ykbryan/domain-watcher/internal/enricher/sources/safebrowsing"
	"github.com/ykbryan/domain-watcher/internal/enricher/sources/urlscan"
	"github.com/ykbryan/domain-watcher/internal/enricher/sources/virustotal"
	"github.com/ykbryan/domain-watcher/internal/pipeline"
	"github.com/ykbryan/domain-watcher/internal/ratelimit"
	"github.com/ykbryan/domain-watcher/internal/resolver"
	"github.com/ykbryan/domain-watcher/internal/store"
	"github.com/ykbryan/domain-watcher/internal/worker"
)

const version = "0.1.0"

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	_ = godotenv.Load()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		slog.Error("DATABASE_URL not set")
		os.Exit(1)
	}

	if err := store.Migrate(dbURL); err != nil {
		slog.Error("migrations failed", "err", err)
		os.Exit(1)
	}
	slog.Info("migrations applied")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbpool, err := store.NewPool(ctx, dbURL)
	if err != nil {
		slog.Error("db connect failed", "err", err)
		os.Exit(1)
	}
	defer dbpool.Close()

	abusechKey := os.Getenv("ABUSECH_AUTH_KEY")
	rl := ratelimit.NewSpecRegistry()

	// No-key sources always register; keyed sources register only if key is set.
	sources := []enricher.Source{
		rdap.New(),
		certwatch.New(),
		abusech.NewURLhaus(abusechKey),
		abusech.NewThreatFox(abusechKey),
		openphish.New(),
		urlscan.New(os.Getenv("URLSCAN_API_KEY"), rl.Get("urlscan")), // search works without a key
	}
	sources = appendIfNotNil(sources,
		virustotal.New(os.Getenv("VIRUSTOTAL_API_KEY"), rl.Get("virustotal")),
		safebrowsing.New(os.Getenv("GOOGLE_SAFE_BROWSING_KEY"), rl.Get("safebrowsing")),
		otx.New(os.Getenv("OTX_API_KEY"), rl.Get("otx")),
		ipinfo.New(os.Getenv("IPINFO_TOKEN"), rl.Get("ipinfo")),
		abuseipdb.New(os.Getenv("ABUSEIPDB_API_KEY"), rl.Get("abuseipdb")),
	)
	slog.Info("enrichers registered", "count", len(sources))
	for _, s := range sources {
		slog.Info("enricher", "name", s.Name())
	}

	resolverCfg := resolver.Config{Upstreams: parseUpstreams(os.Getenv("DNS_UPSTREAMS"))}
	scanJobs := store.NewScanJobs(dbpool)
	permStore := store.NewPermutations(dbpool)
	findingStore := store.NewFindings(dbpool)

	// Sync /scans/quick handler.
	scans := handlers.NewScans(scanJobs, permStore, findingStore, handlers.ScansConfig{
		Resolver:        resolverCfg,
		EnricherSources: sources,
	})

	// Worker pool for async /scans.
	pool := worker.New(
		worker.Config{
			Workers:   envInt("SCAN_WORKER_COUNT", 3),
			QueueSize: 100,
			JobBudget: time.Duration(envInt("SCAN_TIMEOUT_SECONDS", 120)) * time.Second,
		},
		scanJobs, permStore, findingStore,
		pipeline.Options{
			MaxPerms:          envInt("MAX_PERMUTATIONS", 2000),
			IncludeDictionary: true,
			EnrichTopN:        0, // async enriches all live
			ResolverCfg:       resolverCfg,
			Sources:           sources,
		},
	)
	pool.Start(ctx)

	async := handlers.NewAsyncScans(scanJobs, permStore, findingStore, pool)

	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Get("/healthz", handlers.Health(dbpool, version))
	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/scans/quick", scans.PostQuick)
		r.Post("/scans", async.Post)
		r.Get("/scans/{id}", async.Get)
		r.Get("/scans/{id}/results", async.GetResults)
		r.Get("/scans/{id}/report", async.GetReport)
	})

	addr := ":" + getEnv("PORT", "8080")
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	go func() {
		slog.Info("api listening", "addr", addr, "version", version)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server error", "err", err)
			cancel()
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case <-stop:
	case <-ctx.Done():
	}

	slog.Info("shutting down")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("http shutdown error", "err", err)
	}
	if err := pool.Shutdown(shutdownCtx); err != nil {
		slog.Error("worker pool shutdown error", "err", err)
	}
}

func getEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// appendIfNotNil accepts concrete *Source pointers; a nil pointer means the
// source's required API key was missing, so we skip it.
func appendIfNotNil(base []enricher.Source, maybe ...enricher.Source) []enricher.Source {
	for _, s := range maybe {
		if !isNilSource(s) {
			base = append(base, s)
		}
	}
	return base
}

// isNilSource checks for typed-nil interface values (the "s == nil" trap).
// Each constructor returns either *T or a nil *T — when we stuff a nil *T
// into a non-nil interface, the interface itself is not nil.
func isNilSource(s enricher.Source) bool {
	if s == nil {
		return true
	}
	switch v := s.(type) {
	case *virustotal.Source:
		return v == nil
	case *safebrowsing.Source:
		return v == nil
	case *otx.Source:
		return v == nil
	case *ipinfo.Source:
		return v == nil
	case *abuseipdb.Source:
		return v == nil
	case *urlscan.Source:
		return v == nil
	}
	return false
}

func parseUpstreams(csv string) []string {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			if !strings.Contains(p, ":") {
				p += ":53"
			}
			out = append(out, p)
		}
	}
	return out
}
