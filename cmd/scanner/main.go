package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/ykbryan/domain-watcher/internal/permutation"
)

func main() {
	domain := flag.String("domain", "", "target domain (e.g. example.com)")
	max := flag.Int("max", 2000, "max permutations returned")
	noDict := flag.Bool("no-dict", false, "disable dictionary prepend/append patterns")
	flag.Parse()

	if *domain == "" {
		fmt.Fprintln(os.Stderr, "usage: scanner --domain example.com [--max 2000] [--no-dict]")
		os.Exit(2)
	}

	perms, err := permutation.Generate(context.Background(), *domain, permutation.Options{
		Max:               *max,
		IncludeDictionary: !*noDict,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate failed: %v\n", err)
		os.Exit(1)
	}

	for _, p := range perms {
		fmt.Println(p)
	}
}
