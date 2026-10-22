// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

// Command workload loads the shared Coraza workload, runs every case through
// the Go lifecycle and emits the language-neutral NDJSON outcome document.
//
// Run from the Go module directory:
//
//	GOWORK=off GOTOOLCHAIN=local go run ./cmd/workload [--workloads <dir>] [--outcome <file>]
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	bench "github.com/corazawaf/coraza-rs/benchmarks/coraza/go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "coraza workload driver failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	flags := flag.NewFlagSet("coraza-workload", flag.ContinueOnError)
	workloads := flags.String("workloads", "", "workload directory (default ../workloads from the Go module)")
	outcomePath := flags.String("outcome", "", "NDJSON outcome file (default standard output)")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	root := *workloads
	if root == "" {
		defaultRoot, err := defaultWorkloads()
		if err != nil {
			return err
		}
		root = defaultRoot
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve workload directory %s: %w", root, err)
	}
	cases, err := bench.LoadWorkload(absoluteRoot)
	if err != nil {
		return err
	}
	defer func() {
		for _, prepared := range cases {
			_ = prepared.Close()
		}
	}()

	outcomes := make([]bench.Outcome, 0, len(cases))
	for _, prepared := range cases {
		outcome, err := bench.RunCase(prepared)
		if err != nil {
			return err
		}
		if err := bench.CheckExpected(prepared, outcome); err != nil {
			return fmt.Errorf("outcome mismatch: %w", err)
		}
		outcomes = append(outcomes, outcome)
		fmt.Fprintf(os.Stderr, "case %s: pass\n", prepared.ID)
	}
	if *outcomePath == "" {
		if err := bench.WriteOutcomes(os.Stdout, outcomes); err != nil {
			return err
		}
	} else if err := bench.WriteOutcomesFile(*outcomePath, outcomes); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%d cases passed\n", len(cases))
	return nil
}

// defaultWorkloads resolves the same workload directory the Rust driver uses
// by default, relative to the Go module root.
func defaultWorkloads() (string, error) {
	root, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return "", fmt.Errorf("run from the Go module directory or pass --workloads: %w", err)
	}
	return filepath.Join(root, "..", "workloads"), nil
}
