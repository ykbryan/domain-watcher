package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/ykbryan/domain-watcher/internal/permutation"
	"github.com/ykbryan/domain-watcher/internal/resolver"
)

func main() {
	domain := flag.String("domain", "", "target domain (e.g. example.com)")
	max := flag.Int("max", 2000, "max permutations returned")
	noDict := flag.Bool("no-dict", false, "disable dictionary prepend/append patterns")
	resolveFlag := flag.Bool("resolve", false, "resolve DNS for each permutation, print only live ones")
	workers := flag.Int("workers", 50, "concurrent DNS workers (only with --resolve)")
	flag.Parse()

	if *domain == "" {
		fmt.Fprintln(os.Stderr, "usage: scanner --domain example.com [--max 2000] [--no-dict] [--resolve] [--workers 50]")
		os.Exit(2)
	}

	ctx := context.Background()
	perms, err := permutation.Generate(ctx, *domain, permutation.Options{
		Max:               *max,
		IncludeDictionary: !*noDict,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate failed: %v\n", err)
		os.Exit(1)
	}

	if !*resolveFlag {
		for _, p := range perms {
			fmt.Println(p)
		}
		return
	}

	r := resolver.New(resolver.Config{Workers: *workers})
	start := time.Now()
	results := resolver.LiveOnly(r.Resolve(ctx, perms))
	elapsed := time.Since(start)

	for _, res := range results {
		fmt.Printf("%s\tA=%s\tMX=%s\tNS=%s\n",
			res.Domain,
			joinIPs(res.A),
			strings.Join(res.MX, ","),
			strings.Join(res.NS, ","),
		)
	}
	fmt.Fprintf(os.Stderr, "resolved %d/%d live in %s\n", len(results), len(perms), elapsed)
}

func joinIPs(ips []net.IP) string {
	if len(ips) == 0 {
		return ""
	}
	parts := make([]string, len(ips))
	for i, ip := range ips {
		parts[i] = ip.String()
	}
	return strings.Join(parts, ",")
}
