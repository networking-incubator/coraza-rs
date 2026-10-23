// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// benchFixture is the shared end-to-end setup for bench tests.
type benchFixture struct {
	workloadRoot string
	workload     *workload
	outputRoot   string
	work         string
	goModule     string
	checkresolve string
	parity       string
	rustTiming   string
	goTiming     string
	orderLog     string
	buildLog     string
	rustDriver   string
	goDriver     string
	rustBuild    string
	goBuild      string
}

// newBenchFixture creates mock checkresolve, parity, build and driver commands
// for a synthetic workload.
func newBenchFixture(t *testing.T, caseIDs ...string) *benchFixture {
	t.Helper()
	workloadRoot, workload := makeWorkload(t, caseIDs...)
	fixture := &benchFixture{
		workloadRoot: workloadRoot,
		workload:     workload,
		outputRoot:   t.TempDir(),
		work:         t.TempDir(),
		goModule:     makeGoModule(t),
	}
	fixture.checkresolve = checkresolveCommand(t, fixture.work, "upstream", "", false)
	fixture.parity = writeShellScript(t, fixture.work, "parity.sh", "exit 0\n")
	rustSamples := make(map[string][]int64, len(workload.Cases))
	goSamples := make(map[string][]int64, len(workload.Cases))
	for index, entry := range workload.Cases {
		base := int64(index * 1000)
		rustSamples[entry.CaseID] = []int64{base + 100, base + 200, base + 300}
		goSamples[entry.CaseID] = []int64{base + 50, base + 60, base + 70}
	}
	fixture.rustTiming = writeTimingFile(t, fixture.work, "rust-timing.json", "rust", workload, 5, rustSamples)
	fixture.goTiming = writeTimingFile(t, fixture.work, "go-timing.json", "go", workload, 5, goSamples)
	fixture.orderLog = filepath.Join(fixture.work, "order.log")
	fixture.buildLog = filepath.Join(fixture.work, "build.log")
	fixture.rustDriver = writeDriverScript(t, fixture.work, "rust-driver.sh", "rust", fixture.rustTiming, fixture.orderLog)
	fixture.goDriver = writeDriverScript(t, fixture.work, "go-driver.sh", "go", fixture.goTiming, fixture.orderLog)
	fixture.rustBuild = writeBuildScript(t, fixture.work, "rust-build.sh", "rust", fixture.buildLog)
	fixture.goBuild = writeBuildScript(t, fixture.work, "go-build.sh", "go", fixture.buildLog)
	return fixture
}

// args returns the bench flags for the fixture.
func (f *benchFixture) args() []string {
	args := benchArgs(defaultRepoRoot(), f.workloadRoot, f.outputRoot, f.goModule, f.checkresolve, f.parity, f.rustDriver, f.goDriver)
	return append(args, "--rust-build-command", f.rustBuild, "--go-build-command", f.goBuild)
}

// TestBenchEndToEnd runs the full protocol with mock drivers.
func TestBenchEndToEnd(t *testing.T) {
	clearCoordinatorEnv(t)
	fixture := newBenchFixture(t, "case-a", "case-b")
	requireNoError(t, runBenchCommand(fixture.args()))
	runDir := findRunDir(t, fixture.outputRoot)
	result := readBenchResult(t, runDir)

	requireEqual(t, result.SchemaVersion, resultSchemaVersion)
	requireEqual(t, result.Status, "passed")
	requireEqual(t, result.Error, "")
	requireEqual(t, result.Protocol.Repetitions, 3)
	requireEqual(t, result.Protocol.Iterations, 5)
	requireEqual(t, result.Protocol.TimingContract, "1")
	requireEqual(t, result.Identity.GoEngine.Profile, "upstream")
	requireEqual(t, result.Parity.Passed, true)
	requireEqual(t, len(result.Runs), 6)

	// Alternating order: every round flips which engine runs first.
	var engines []string
	for _, run := range result.Runs {
		engines = append(engines, run.Engine)
		if _, err := os.Stat(filepath.Join(runDir, run.RawTiming)); err != nil {
			t.Fatalf("raw timing artifact %s: %v", run.RawTiming, err)
		}
		if _, err := os.Stat(filepath.Join(runDir, run.Stdout)); err != nil {
			t.Fatalf("stdout artifact %s: %v", run.Stdout, err)
		}
		if _, err := os.Stat(filepath.Join(runDir, run.Stderr)); err != nil {
			t.Fatalf("stderr artifact %s: %v", run.Stderr, err)
		}
	}
	requireEqual(t, strings.Join(engines, ","), "rust,go,go,rust,rust,go")
	requireEqual(t, strings.Join(readLines(t, fixture.orderLog), ","), "rust,go,go,rust,rust,go")
	// Drivers are built exactly once each.
	requireEqual(t, strings.Join(readLines(t, fixture.buildLog), ","), "rust,go")
	requireEqual(t, result.Identity.Commands.RustDriver.Command, fixture.rustDriver)
	requireEqual(t, result.Identity.Commands.GoDriver.Command, fixture.goDriver)
	requireEqual(t, result.Identity.Commands.RustBuild.Command, fixture.rustBuild)
	requireEqual(t, result.Identity.Commands.GoBuild.Command, fixture.goBuild)

	requireEqual(t, len(result.Cases), 2)
	first := result.Cases[0]
	requireEqual(t, first.CaseID, "case-a")
	requireEqual(t, first.Correctness, "passed")
	// Three repetitions of three samples each are pooled per case and engine.
	requireEqual(t, first.Engines["rust"].SampleCount, 9)
	requireEqual(t, first.Engines["rust"].MedianNS, float64(200))
	requireEqual(t, first.Engines["go"].SampleCount, 9)
	requireEqual(t, first.Engines["go"].MedianNS, float64(60))
	if first.RatioRustOverGo == nil || math.Abs(*first.RatioRustOverGo-200.0/60.0) > 1e-9 {
		t.Fatalf("unexpected ratio: %v", first.RatioRustOverGo)
	}
}

// TestBenchStopsOnParityFailure verifies that a failed correctness gate stops
// before builds and timing.
func TestBenchStopsOnParityFailure(t *testing.T) {
	clearCoordinatorEnv(t)
	fixture := newBenchFixture(t, "case-a")
	fixture.parity = writeShellScript(t, fixture.work, "parity-fail.sh", "echo 'case-a diverged' >&2\nexit 3\n")
	err := runBenchCommand(fixture.args())
	requireError(t, err)
	if !strings.Contains(err.Error(), "correctness parity gate failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	runDir := findRunDir(t, fixture.outputRoot)
	result := readBenchResult(t, runDir)
	requireEqual(t, result.Status, "failed")
	requireEqual(t, result.Parity.Attempted, true)
	requireEqual(t, result.Parity.Passed, false)
	requireEqual(t, result.Parity.ExitCode, 3)
	requireEqual(t, len(result.Runs), 0)
	if lines := readLines(t, fixture.buildLog); len(lines) != 0 {
		t.Fatalf("drivers were built after a parity failure: %v", lines)
	}
	if lines := readLines(t, fixture.orderLog); len(lines) != 0 {
		t.Fatalf("drivers ran after a parity failure: %v", lines)
	}
	parityStderr, readErr := os.ReadFile(filepath.Join(runDir, result.Parity.Stderr))
	requireNoError(t, readErr)
	if !strings.Contains(string(parityStderr), "case-a diverged") {
		t.Fatalf("parity stderr was not preserved: %q", parityStderr)
	}
}

// TestBenchStopsOnCheckresolveFailure verifies that identity validation
// happens before the parity gate or any driver.
func TestBenchStopsOnCheckresolveFailure(t *testing.T) {
	clearCoordinatorEnv(t)
	fixture := newBenchFixture(t, "case-a")
	fixture.checkresolve = writeShellScript(t, fixture.work, "checkresolve-fail.sh", "echo 'engine dirty' >&2\nexit 4\n")
	marker := filepath.Join(fixture.work, "parity-ran")
	fixture.parity = writeShellScript(t, fixture.work, "parity.sh", "touch "+shellQuote(marker)+"\nexit 0\n")
	err := runBenchCommand(fixture.args())
	requireError(t, err)
	if !strings.Contains(err.Error(), "checkresolve failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("parity ran after a checkresolve failure")
	}
	runDir := findRunDir(t, fixture.outputRoot)
	result := readBenchResult(t, runDir)
	requireEqual(t, result.Status, "failed")
	requireEqual(t, result.Parity.Attempted, false)
	requireEqual(t, len(result.Runs), 0)
}

// TestBenchRejectsInvalidTiming verifies that malformed driver output stops
// the protocol and is preserved as evidence.
func TestBenchRejectsInvalidTiming(t *testing.T) {
	clearCoordinatorEnv(t)
	fixture := newBenchFixture(t, "case-a")
	fixture.rustTiming = writeTestFile(t, fixture.work, "rust-invalid.json", "{")
	fixture.rustDriver = writeDriverScript(t, fixture.work, "rust-invalid-driver.sh", "rust", fixture.rustTiming, fixture.orderLog)
	err := runBenchCommand(fixture.args())
	requireError(t, err)
	if !strings.Contains(err.Error(), "timing output") {
		t.Fatalf("unexpected error: %v", err)
	}
	runDir := findRunDir(t, fixture.outputRoot)
	result := readBenchResult(t, runDir)
	requireEqual(t, result.Status, "failed")
	requireEqual(t, len(result.Runs), 1)
	requireEqual(t, len(result.Cases), 0)
	if _, statErr := os.Stat(filepath.Join(runDir, result.Runs[0].RawTiming)); statErr != nil {
		t.Fatalf("raw timing output was not preserved: %v", statErr)
	}
}

// TestBenchRejectsIncompleteTiming verifies the case-set check.
func TestBenchRejectsIncompleteTiming(t *testing.T) {
	clearCoordinatorEnv(t)
	fixture := newBenchFixture(t, "case-a", "case-b")
	incomplete := map[string]any{
		"schema_version":  1,
		"engine":          "rust",
		"workload_id":     fixture.workload.ID,
		"manifest_sha256": fixture.workload.ManifestSHA256,
		"iterations":      5,
		"cases": []map[string]any{
			{"case_id": "case-a", "samples_ns": []int64{1, 2}},
		},
	}
	data, err := json.Marshal(incomplete)
	requireNoError(t, err)
	incompletePath := writeTestBytes(t, fixture.work, "rust-incomplete.json", data)
	fixture.rustDriver = writeDriverScript(t, fixture.work, "rust-incomplete-driver.sh", "rust", incompletePath, fixture.orderLog)
	err = runBenchCommand(fixture.args())
	requireError(t, err)
	if !strings.Contains(err.Error(), "missing case") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestBenchPublishesDivergentCases verifies that only gate-passing cases get a
// ratio and that every workload case is published.
func TestBenchPublishesDivergentCases(t *testing.T) {
	clearCoordinatorEnv(t)
	fixture := newBenchFixture(t, "case-a", "case-b", "case-c")
	report := map[string]any{
		"schema_version": 1,
		"cases": []map[string]any{
			{"case_id": "case-a", "status": "passed"},
			{"case_id": "case-b", "status": "divergent", "reason": "matched rules differ"},
		},
	}
	data, err := json.Marshal(report)
	requireNoError(t, err)
	reportPath := writeTestBytes(t, fixture.work, "parity-report.json", data)
	args := append(fixture.args(), "--parity-report", reportPath)
	requireNoError(t, runBenchCommand(args))
	runDir := findRunDir(t, fixture.outputRoot)
	result := readBenchResult(t, runDir)
	requireEqual(t, result.Status, "passed")
	requireEqual(t, len(result.Cases), 3)
	requireEqual(t, result.Cases[0].CaseID, "case-a")
	requireEqual(t, result.Cases[0].Correctness, "passed")
	if result.Cases[0].RatioRustOverGo == nil {
		t.Fatal("passing case must have a ratio")
	}
	requireEqual(t, result.Cases[1].Correctness, "divergent")
	requireEqual(t, result.Cases[1].Reason, "matched rules differ")
	if result.Cases[1].RatioRustOverGo != nil {
		t.Fatal("divergent case must not have a ratio")
	}
	requireEqual(t, result.Cases[2].Correctness, "ineligible")
	if result.Cases[2].RatioRustOverGo != nil {
		t.Fatal("ineligible case must not have a ratio")
	}
}

// TestParseConfigIterationBound verifies that the iteration CLI bound equals
// the per-case sample bound: 1000000 is accepted and 1000001 is rejected.
func TestParseConfigIterationBound(t *testing.T) {
	clearCoordinatorEnv(t)
	cfg, err := parseConfig("bench", []string{"--iterations", "1000000"})
	requireNoError(t, err)
	requireEqual(t, cfg.iterations, maxSamplesPerCase)

	clearCoordinatorEnv(t)
	_, err = parseConfig("bench", []string{"--iterations", "1000001"})
	requireError(t, err)
	if !strings.Contains(err.Error(), "1000000") {
		t.Fatalf("error does not name the iteration bound: %v", err)
	}
}

// TestParseConfigRejectsInvalidValues covers protocol preconditions.
func TestParseConfigRejectsInvalidValues(t *testing.T) {
	tests := [][]string{
		{"--repetitions", "2"},
		{"--iterations", "0"},
		{"--iterations", "1000001"},
		{"--go-profile", "vendor"},
		{"--rust-build-command", "true"},
		{"--go-build-command", "true"},
		{"--unknown-flag"},
		{"unexpected"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			clearCoordinatorEnv(t)
			_, err := parseConfig("bench", args)
			requireError(t, err)
		})
	}
}
