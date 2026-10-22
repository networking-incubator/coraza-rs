// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

// Command parity builds both workload drivers, runs them over the same
// workload and fails on any per-case, per-field outcome divergence.
//
// Run from the Go module directory:
//
//	GOWORK=off GOTOOLCHAIN=local go run ./cmd/parity [--workloads <dir>]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	bench "github.com/corazawaf/coraza-rs/benchmarks/coraza/go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "coraza parity runner failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	flags := flag.NewFlagSet("coraza-parity", flag.ContinueOnError)
	workloads := flags.String("workloads", "", "workload directory (default ../workloads from the Go module)")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	moduleRoot, err := moduleRoot()
	if err != nil {
		return err
	}
	repoRoot := filepath.Clean(filepath.Join(moduleRoot, "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(repoRoot, "coraza", "benches", "coraza_workload.rs")); err != nil {
		return fmt.Errorf("cannot find the Rust driver under %s: %w", repoRoot, err)
	}
	root := *workloads
	if root == "" {
		root = filepath.Join(moduleRoot, "..", "workloads")
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve workload directory %s: %w", root, err)
	}

	temporary, err := os.MkdirTemp("", "coraza-parity-")
	if err != nil {
		return fmt.Errorf("create temporary directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(temporary)
	}()
	goBinary := filepath.Join(temporary, "coraza-workload")
	rustOutcomes := filepath.Join(temporary, "rust.ndjson")
	goOutcomes := filepath.Join(temporary, "go.ndjson")

	ctx := context.Background()
	if output, err := runCommand(ctx, moduleRoot, goEnv(), "go", "build", "-o", goBinary, "./cmd/workload"); err != nil {
		return fmt.Errorf("build Go driver: %w: %s", err, output)
	}
	if output, err := runCommand(
		ctx, moduleRoot, nil, goBinary, "--workloads", absoluteRoot, "--outcome", goOutcomes,
	); err != nil {
		return fmt.Errorf("run Go driver: %w: %s", err, output)
	}
	if output, err := runCommand(
		ctx, repoRoot, nil,
		"cargo", "bench", "-p", "coraza", "--bench", "coraza_workload", "--",
		"--workloads", absoluteRoot, "--outcome", rustOutcomes,
	); err != nil {
		return fmt.Errorf("run Rust driver: %w: %s", err, output)
	}

	rustDocument, err := bench.ReadOutcomesFile(rustOutcomes)
	if err != nil {
		return fmt.Errorf("Rust driver output: %w", err)
	}
	goDocument, err := bench.ReadOutcomesFile(goOutcomes)
	if err != nil {
		return fmt.Errorf("Go driver output: %w", err)
	}
	divergences := bench.CompareOutcomes(rustDocument, goDocument)
	if len(divergences) > 0 {
		for _, divergence := range divergences {
			fmt.Fprintln(os.Stderr, divergence)
		}
		return fmt.Errorf("%d divergence(s) across %d cases", len(divergences), len(rustDocument))
	}
	fmt.Printf("parity passed for %d cases\n", len(rustDocument))
	return nil
}

// moduleRoot returns the Go module directory from the runtime working
// directory, matching the resolution check convention.
func moduleRoot() (string, error) {
	root, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return "", fmt.Errorf("run from the Go module directory, %s has no go.mod: %w", root, err)
	}
	return root, nil
}

// runCommand runs one command and returns its combined output on failure.
func runCommand(ctx context.Context, dir string, env []string, name string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = dir
	if env != nil {
		command.Env = env
	}
	output, err := command.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

// goEnv returns the environment for a Go invocation with workspace and
// toolchain selection pinned, preserving any inherited GOFLAGS.
func goEnv() []string {
	return withEnv(withEnv(os.Environ(), "GOWORK", "off"), "GOTOOLCHAIN", "local")
}

// withEnv replaces key so no duplicate entry can override it.
func withEnv(env []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env)+1)
	for _, entry := range env {
		if !strings.HasPrefix(entry, prefix) {
			out = append(out, entry)
		}
	}
	return append(out, prefix+value)
}
