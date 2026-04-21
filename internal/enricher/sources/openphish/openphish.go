// Package openphish downloads the OpenPhish feed once every feedTTL and
// serves O(1) host-membership lookups from an in-memory set.
package openphish

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ykbryan/domain-watcher/internal/enricher"
)

const (
	sourceName      = "openphish"
	defaultFeedURL  = "https://openphish.com/feed.txt"
	defaultFeedTTL  = 6 * time.Hour
	fetchHTTPTimeout = 15 * time.Second
)

type Source struct {
	feedURL  string
	ttl      time.Duration
	client   *http.Client

	mu        sync.RWMutex
	hosts     map[string]struct{}
	refreshed time.Time
}

func New() *Source {
	return NewWithConfig(defaultFeedURL, defaultFeedTTL)
}

func NewWithConfig(feedURL string, ttl time.Duration) *Source {
	return &Source{
		feedURL: feedURL,
		ttl:     ttl,
		client:  &http.Client{Timeout: fetchHTTPTimeout},
		hosts:   map[string]struct{}{},
	}
}

func (s *Source) Name() string { return sourceName }

func (s *Source) Enrich(ctx context.Context, domain string) (*enricher.Finding, error) {
	if err := s.ensureFresh(ctx); err != nil {
		return nil, err
	}

	s.mu.RLock()
	_, hit := s.hosts[domain]
	s.mu.RUnlock()

	f := &enricher.Finding{SourceName: sourceName}
	if hit {
		f.RiskSignals = append(f.RiskSignals, enricher.RiskSignal{
			Label:    "openphish_match",
			Severity: enricher.SeverityCritical,
			Detail:   "domain present in OpenPhish feed",
		})
	}
	return f, nil
}

func (s *Source) ensureFresh(ctx context.Context) error {
	s.mu.RLock()
	fresh := !s.refreshed.IsZero() && time.Since(s.refreshed) < s.ttl
	s.mu.RUnlock()
	if fresh {
		return nil
	}
	return s.refresh(ctx)
}

func (s *Source) refresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Double-check inside the lock: another goroutine may have just refreshed.
	if !s.refreshed.IsZero() && time.Since(s.refreshed) < s.ttl {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.feedURL, nil)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("openphish feed status %d", resp.StatusCode)
	}

	hosts := make(map[string]struct{}, 8192)
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		host := hostOf(line)
		if host != "" {
			hosts[host] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan feed: %w", err)
	}
	s.hosts = hosts
	s.refreshed = time.Now()
	return nil
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	h := u.Hostname()
	return strings.ToLower(h)
}
