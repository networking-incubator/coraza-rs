// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

// Command bench runs every workload case through the Go lifecycle for a fixed
// number of iterations and writes the timing document consumed by the local
// benchmark coordinator.
//
// One invocation loads and validates the whole workload and compiles every
// policy once, before timing starts. Each iteration then creates one fresh
// transaction, drives connection, URI, request headers, request body, response
// headers, response body, logging and close, and records that transaction's
// elapsed nanoseconds.
//
// Run from the Go module directory:
//
//	GOWORK=off GOTOOLCHAIN=local go run ./cmd/bench --timing <file> --iterations <n>
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	bench "github.com/corazawaf/coraza-rs/benchmarks/coraza/go"
)

const (
	// timingSchemaVersion versions the timing document shared with the
	// coordinator.
	timingSchemaVersion = 1
	// goEngine names the Go driver in the timing document.
	goEngine = "go"
	// maxIterations matches the coordinator's per-case sample bound.
	maxIterations = 1_000_000
)

// timingDocument is the JSON document consumed by the benchmark coordinator.
// It has exactly the fields the coordinator validates, and every case appears
// once in manifest order.
type timingDocument struct {
	SchemaVersion  int          `json:"schema_version"`
	Engine         string       `json:"engine"`
	WorkloadID     string       `json:"workload_id"`
	ManifestSHA256 string       `json:"manifest_sha256"`
	Iterations     int          `json:"iterations"`
	Cases          []timingCase `json:"cases"`
}

// timingCase is one case's per-transaction durations in nanoseconds.
type timingCase struct {
	CaseID    string  `json:"case_id"`
	SamplesNS []int64 `json:"samples_ns"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "coraza timing driver failed: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("coraza-bench", flag.ContinueOnError)
	workloads := flags.String("workloads", "", "workload directory (default ../workloads from the Go module)")
	timingPath := flags.String("timing", "", "timing JSON output file (required)")
	iterations := flags.Int("iterations", 0, "timed iterations per case (1 to 1000000)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	if *timingPath == "" {
		return fmt.Errorf("--timing is required")
	}
	if *iterations < 1 || *iterations > maxIterations {
		return fmt.Errorf("iterations must be between 1 and %d, got %d", maxIterations, *iterations)
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
	cases, info, err := bench.LoadWorkloadWithInfo(absoluteRoot)
	if err != nil {
		return err
	}
	defer func() {
		for _, prepared := range cases {
			_ = prepared.Close()
		}
	}()

	document := timingDocument{
		SchemaVersion:  timingSchemaVersion,
		Engine:         goEngine,
		WorkloadID:     info.ID,
		ManifestSHA256: info.ManifestSHA256,
		Iterations:     *iterations,
		Cases:          make([]timingCase, 0, len(cases)),
	}
	for _, prepared := range cases {
		samples := make([]int64, *iterations)
		for index := range samples {
			elapsed, err := bench.RunTimed(prepared)
			if err != nil {
				return err
			}
			samples[index] = elapsed.Nanoseconds()
		}
		document.Cases = append(document.Cases, timingCase{CaseID: prepared.ID, SamplesNS: samples})
	}
	if err := writeTiming(*timingPath, document); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "timed %d cases at %d iterations\n", len(cases), *iterations)
	return nil
}

// writeTiming writes the document to a temporary file next to path and renames
// it into place, so a failed run never leaves a partial document.
func writeTiming(path string, document timingDocument) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".coraza-timing-*")
	if err != nil {
		return fmt.Errorf("create timing output next to %s: %w", path, err)
	}
	name := temporary.Name()
	defer func() {
		_ = os.Remove(name)
	}()
	encoder := json.NewEncoder(temporary)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write timing output %s: %w", path, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close timing output %s: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("replace timing output %s: %w", path, err)
	}
	return nil
}

// defaultWorkloads resolves the same workload directory the other Go commands
// use by default, relative to the Go module root.
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
