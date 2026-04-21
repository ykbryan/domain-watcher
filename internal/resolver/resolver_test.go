package resolver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// mockDNSServer spins up a local UDP DNS server that answers based on the provided handler.
// Returns the address string (127.0.0.1:PORT) and a shutdown func.
func mockDNSServer(t *testing.T, handler dns.HandlerFunc) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	server := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = server.ActivateAndServe() }()
	return pc.LocalAddr().String(), func() { _ = server.Shutdown() }
}

func TestResolve_LiveDomain(t *testing.T) {
	addr, stop := mockDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		for _, q := range req.Question {
			switch q.Qtype {
			case dns.TypeA:
				rr, _ := dns.NewRR("live.test. 60 IN A 203.0.113.7")
				m.Answer = append(m.Answer, rr)
			case dns.TypeMX:
				rr, _ := dns.NewRR("live.test. 60 IN MX 10 mail.live.test.")
				m.Answer = append(m.Answer, rr)
			case dns.TypeNS:
				rr, _ := dns.NewRR("live.test. 60 IN NS ns1.live.test.")
				m.Answer = append(m.Answer, rr)
			}
		}
		_ = w.WriteMsg(m)
	})
	defer stop()

	r := New(Config{Upstreams: []string{addr}, Workers: 4, Timeout: 2 * time.Second})
	res := r.Resolve(context.Background(), []string{"live.test"})
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	got := res[0]
	if !got.IsLive {
		t.Errorf("want IsLive=true, got false (err=%v)", got.Err)
	}
	if len(got.A) != 1 || got.A[0].String() != "203.0.113.7" {
		t.Errorf("A record mismatch: %v", got.A)
	}
	if len(got.MX) != 1 || got.MX[0] != "mail.live.test." {
		t.Errorf("MX mismatch: %v", got.MX)
	}
	if len(got.NS) != 1 {
		t.Errorf("NS missing: %v", got.NS)
	}
}

func TestResolve_NXDOMAIN(t *testing.T) {
	addr, stop := mockDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
	})
	defer stop()

	r := New(Config{Upstreams: []string{addr}, Workers: 2, Timeout: 1 * time.Second})
	res := r.Resolve(context.Background(), []string{"missing.test"})
	if res[0].IsLive {
		t.Errorf("want IsLive=false for NXDOMAIN, got true")
	}
	if res[0].Err != nil {
		t.Errorf("NXDOMAIN should not be an error, got: %v", res[0].Err)
	}
}

func TestResolve_MXPresenceFlagged(t *testing.T) {
	addr, stop := mockDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		for _, q := range req.Question {
			if q.Qtype == dns.TypeMX {
				rr, _ := dns.NewRR("mxonly.test. 60 IN MX 10 mail.mxonly.test.")
				m.Answer = append(m.Answer, rr)
			}
		}
		_ = w.WriteMsg(m)
	})
	defer stop()

	r := New(Config{Upstreams: []string{addr}, Workers: 2, Timeout: 1 * time.Second})
	res := r.Resolve(context.Background(), []string{"mxonly.test"})
	if !res[0].IsLive {
		t.Errorf("MX-only domain should be flagged live")
	}
	if len(res[0].MX) != 1 {
		t.Errorf("MX should be populated: %v", res[0].MX)
	}
	if len(res[0].A) != 0 {
		t.Errorf("A should be empty for MX-only: %v", res[0].A)
	}
}

func TestResolve_ManyDomainsConcurrent(t *testing.T) {
	addr, stop := mockDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		for _, q := range req.Question {
			if q.Qtype == dns.TypeA {
				rr, _ := dns.NewRR(q.Name + " 60 IN A 203.0.113.1")
				m.Answer = append(m.Answer, rr)
			}
		}
		_ = w.WriteMsg(m)
	})
	defer stop()

	domains := make([]string, 100)
	for i := range domains {
		domains[i] = "test.local"
	}
	r := New(Config{Upstreams: []string{addr}, Workers: 50, Timeout: 2 * time.Second})
	start := time.Now()
	res := r.Resolve(context.Background(), domains)
	elapsed := time.Since(start)
	if len(res) != 100 {
		t.Fatalf("want 100 results, got %d", len(res))
	}
	if elapsed > 5*time.Second {
		t.Errorf("100 concurrent resolutions took %v (expected <5s)", elapsed)
	}
	live := LiveOnly(res)
	if len(live) != 100 {
		t.Errorf("want 100 live, got %d", len(live))
	}
}

func TestResolve_ContextCancel(t *testing.T) {
	addr, stop := mockDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		time.Sleep(500 * time.Millisecond)
		m := new(dns.Msg)
		m.SetReply(req)
		_ = w.WriteMsg(m)
	})
	defer stop()

	r := New(Config{Upstreams: []string{addr}, Workers: 5, Timeout: 2 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	res := r.Resolve(ctx, []string{"slow.test"})
	if res[0].IsLive {
		t.Errorf("expected not-live after context cancel")
	}
}

func TestLiveOnly(t *testing.T) {
	in := []Result{
		{Domain: "a", IsLive: true},
		{Domain: "b", IsLive: false},
		{Domain: "c", IsLive: true},
	}
	out := LiveOnly(in)
	if len(out) != 2 {
		t.Fatalf("want 2, got %d", len(out))
	}
	if out[0].Domain != "a" || out[1].Domain != "c" {
		t.Errorf("order not preserved: %v", out)
	}
}
