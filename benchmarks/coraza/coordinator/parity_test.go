// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParitySubcommandSuccess runs the parity-only orchestration with a mock
// runner that succeeds.
func TestParitySubcommandSuccess(t *testing.T) {
	clearCoordinatorEnv(t)
	workloadRoot, _ := makeWorkload(t, "case-a", "case-b")
	outputRoot := t.TempDir()
	work := t.TempDir()
	goModule := makeGoModule(t)
	checkresolve := checkresolveCommand(t, work, "upstream", "", false)
	parity := writeShellScript(t, work, "parity.sh", "echo 'all cases matched'\nexit 0\n")
	requireNoError(t, runParityCommand(parityArgs(defaultRepoRoot(), workloadRoot, outputRoot, goModule, checkresolve, parity)))
	runDir := findRunDir(t, outputRoot)
	document := readParityDocument(t, runDir)
	requireEqual(t, document.Status, "passed")
	requireEqual(t, document.Error, "")
	requireEqual(t, document.Parity.Attempted, true)
	requireEqual(t, document.Parity.Passed, true)
	requireEqual(t, document.Parity.ExitCode, 0)
	requireEqual(t, document.Identity.GoEngine.Profile, "upstream")
	if _, err := os.Stat(filepath.Join(runDir, "identity.json")); err != nil {
		t.Fatalf("identity artifact: %v", err)
	}
	stdout, err := os.ReadFile(filepath.Join(runDir, document.Parity.Stdout))
	requireNoError(t, err)
	if !strings.Contains(string(stdout), "all cases matched") {
		t.Fatalf("parity stdout was not preserved: %q", stdout)
	}
}

// TestParitySubcommandFailure records a failing runner and returns an error.
func TestParitySubcommandFailure(t *testing.T) {
	clearCoordinatorEnv(t)
	workloadRoot, _ := makeWorkload(t, "case-a")
	outputRoot := t.TempDir()
	work := t.TempDir()
	goModule := makeGoModule(t)
	checkresolve := checkresolveCommand(t, work, "upstream", "", false)
	parity := writeShellScript(t, work, "parity.sh", "echo 'case-a mismatch' >&2\nexit 2\n")
	err := runParityCommand(parityArgs(defaultRepoRoot(), workloadRoot, outputRoot, goModule, checkresolve, parity))
	requireError(t, err)
	runDir := findRunDir(t, outputRoot)
	document := readParityDocument(t, runDir)
	requireEqual(t, document.Status, "failed")
	requireEqual(t, document.Parity.Attempted, true)
	requireEqual(t, document.Parity.Passed, false)
	requireEqual(t, document.Parity.ExitCode, 2)
	if !strings.Contains(document.Error, "correctness parity gate failed") {
		t.Fatalf("unexpected error field: %q", document.Error)
	}
	stderr, readErr := os.ReadFile(filepath.Join(runDir, document.Parity.Stderr))
	requireNoError(t, readErr)
	if !strings.Contains(string(stderr), "case-a mismatch") {
		t.Fatalf("parity stderr was not preserved: %q", stderr)
	}
}

// TestParityRejectsDirtyLocalEngine stops before the runner when checkresolve
// reports a modified local checkout.
func TestParityRejectsDirtyLocalEngine(t *testing.T) {
	clearCoordinatorEnv(t)
	workloadRoot, _ := makeWorkload(t, "case-a")
	outputRoot := t.TempDir()
	work := t.TempDir()
	goModule := makeGoModule(t)
	// checkresolve exits zero but reports a dirty engine: the coordinator must
	// still refuse the run.
	checkresolve := checkresolveCommand(t, work, "local", strings.Repeat("b", 40), true)
	marker := filepath.Join(work, "parity-ran")
	parity := writeShellScript(t, work, "parity.sh", "touch "+shellQuote(marker)+"\nexit 0\n")
	err := runParityCommand(parityArgs(defaultRepoRoot(), workloadRoot, outputRoot, goModule, checkresolve, parity))
	requireError(t, err)
	if !strings.Contains(err.Error(), "engine checkout has local modifications") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatal("parity ran despite a dirty local engine")
	}
}
