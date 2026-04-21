package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"

	"github.com/ykbryan/domain-watcher/api/handlers"
	"github.com/ykbryan/domain-watcher/internal/enricher"
	"github.com/ykbryan/domain-watcher/internal/enricher/sources/abusech"
	"github.com/ykbryan/domain-watcher/internal/enricher/sources/certwatch"
	"github.com/ykbryan/domain-watcher/internal/enricher/sources/openphish"
	"github.com/ykbryan/domain-watcher/internal/enricher/sources/rdap"
	"github.com/ykbryan/domain-watcher/internal/resolver"
	"github.com/ykbryan/domain-watcher/internal/store"
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

	pool, err := store.NewPool(ctx, dbURL)
	if err != nil {
		slog.Error("db connect failed", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	abusechKey := os.Getenv("ABUSECH_AUTH_KEY")
	sources := []enricher.Source{
		rdap.New(),
		certwatch.New(),
		abusech.NewURLhaus(abusechKey),
		abusech.NewThreatFox(abusechKey),
		openphish.New(),
	}

	scans := handlers.NewScans(
		store.NewScanJobs(pool),
		store.NewPermutations(pool),
		store.NewFindings(pool),
		handlers.ScansConfig{
			Resolver: resolver.Config{Upstreams: parseUpstreams(os.Getenv("DNS_UPSTREAMS"))},
			Enricher: handlers.EnricherConfig{Sources: sources},
		},
	)

	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Get("/healthz", handlers.Health(pool, version))
	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/scans/quick", scans.PostQuick)
	})

	addr := ":" + getEnv("PORT", "8080")
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 60 * time.Second, // /scans/quick can run up to 30s
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
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "err", err)
	}
}

func getEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
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
