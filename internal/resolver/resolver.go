// Package resolver performs concurrent DNS lookups (A, AAAA, MX, NS) across
// a worker pool with upstream rotation and retry.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DefaultUpstreams are public DNS resolvers used unless overridden.
var DefaultUpstreams = []string{
	"8.8.8.8:53",
	"1.1.1.1:53",
	"9.9.9.9:53",
}

// Result is the outcome of resolving a single domain across four record types.
type Result struct {
	Domain string
	A      []net.IP
	AAAA   []net.IP
	MX     []string
	NS     []string
	IsLive bool
	Err    error
}

// Config tunes the resolver.
type Config struct {
	Workers   int           // default 50
	Upstreams []string      // default DefaultUpstreams
	Timeout   time.Duration // per-query; default 3s
	Retries   int           // default 1
}

// Resolver is safe for concurrent use.
type Resolver struct {
	cfg    Config
	client *dns.Client
}

// New returns a Resolver with sensible defaults applied.
func New(cfg Config) *Resolver {
	if cfg.Workers <= 0 {
		cfg.Workers = 50
	}
	if len(cfg.Upstreams) == 0 {
		cfg.Upstreams = DefaultUpstreams
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.Retries < 0 {
		cfg.Retries = 0
	} else if cfg.Retries == 0 {
		cfg.Retries = 1
	}
	return &Resolver{
		cfg:    cfg,
		client: &dns.Client{Timeout: cfg.Timeout},
	}
}

// Resolve runs concurrent A/AAAA/MX/NS lookups for every input domain.
// Results are returned in the same order as input.
func (r *Resolver) Resolve(ctx context.Context, domains []string) []Result {
	results := make([]Result, len(domains))
	sem := make(chan struct{}, r.cfg.Workers)
	var wg sync.WaitGroup

	for i, d := range domains {
		select {
		case <-ctx.Done():
			results[i] = Result{Domain: d, Err: ctx.Err()}
			continue
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(idx int, domain string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx] = r.resolveOne(ctx, domain)
		}(i, d)
	}
	wg.Wait()
	return results
}

func (r *Resolver) resolveOne(ctx context.Context, domain string) Result {
	res := Result{Domain: domain}

	type answer struct {
		qtype uint16
		rrs   []dns.RR
		err   error
	}
	ch := make(chan answer, 4)
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeNS} {
		qt := qt
		go func() {
			rrs, err := r.query(ctx, domain, qt)
			ch <- answer{qtype: qt, rrs: rrs, err: err}
		}()
	}

	var errs []error
	for i := 0; i < 4; i++ {
		a := <-ch
		if a.err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", dns.TypeToString[a.qtype], a.err))
			continue
		}
		switch a.qtype {
		case dns.TypeA:
			for _, rr := range a.rrs {
				if v, ok := rr.(*dns.A); ok {
					res.A = append(res.A, v.A)
				}
			}
		case dns.TypeAAAA:
			for _, rr := range a.rrs {
				if v, ok := rr.(*dns.AAAA); ok {
					res.AAAA = append(res.AAAA, v.AAAA)
				}
			}
		case dns.TypeMX:
			for _, rr := range a.rrs {
				if v, ok := rr.(*dns.MX); ok {
					res.MX = append(res.MX, v.Mx)
				}
			}
		case dns.TypeNS:
			for _, rr := range a.rrs {
				if v, ok := rr.(*dns.NS); ok {
					res.NS = append(res.NS, v.Ns)
				}
			}
		}
	}

	res.IsLive = len(res.A) > 0 || len(res.AAAA) > 0 || len(res.MX) > 0 || len(res.NS) > 0
	if !res.IsLive && len(errs) > 0 {
		res.Err = errors.Join(errs...)
	}
	return res
}

// query issues a single DNS question with retry across rotating upstreams.
// NXDOMAIN and empty success responses are returned as (nil, nil) — not-live,
// not an error.
func (r *Resolver) query(ctx context.Context, domain string, qtype uint16) ([]dns.RR, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.RecursionDesired = true

	attempts := r.cfg.Retries + 1
	var lastErr error
	for i := 0; i < attempts; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		upstream := r.cfg.Upstreams[rand.IntN(len(r.cfg.Upstreams))]

		qCtx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
		resp, _, err := r.client.ExchangeContext(qCtx, msg, upstream)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		switch resp.Rcode {
		case dns.RcodeSuccess:
			return resp.Answer, nil
		case dns.RcodeNameError: // NXDOMAIN
			return nil, nil
		default:
			lastErr = fmt.Errorf("rcode %s", dns.RcodeToString[resp.Rcode])
		}
	}
	return nil, lastErr
}

// LiveOnly returns the subset of results where IsLive is true.
func LiveOnly(results []Result) []Result {
	out := make([]Result, 0, len(results))
	for _, r := range results {
		if r.IsLive {
			out = append(out, r)
		}
	}
	return out
}
