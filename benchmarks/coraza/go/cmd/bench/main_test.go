// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// shippedWorkloadRoot returns the workload directory shipped next to the Go
// module. Tests run with the package directory as the working directory.
func shippedWorkloadRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "..", "workloads"))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// TestTimingDocumentShape validates the exact document fields, case set and
// order, sample counts and non-negative samples.
func TestTimingDocumentShape(t *testing.T) {
	root := shippedWorkloadRoot(t)
	output := filepath.Join(t.TempDir(), "timing.json")
	if err := run([]string{"--workloads", root, "--timing", output, "--iterations", "2"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("timing document is not valid JSON: %v", err)
	}
	keys := make([]string, 0, len(document))
	for key := range document {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	wantKeys := []string{
		"cases",
		"engine",
		"iterations",
		"manifest_sha256",
		"schema_version",
		"workload_id",
	}
	if strings.Join(keys, ",") != strings.Join(wantKeys, ",") {
		t.Fatalf("document fields = %v, want %v", keys, wantKeys)
	}
	var schemaVersion int
	if err := json.Unmarshal(document["schema_version"], &schemaVersion); err != nil {
		t.Fatal(err)
	}
	if schemaVersion != 1 {
		t.Fatalf("schema_version = %d, want 1", schemaVersion)
	}
	var engine string
	if err := json.Unmarshal(document["engine"], &engine); err != nil {
		t.Fatal(err)
	}
	if engine != "go" {
		t.Fatalf("engine = %q, want go", engine)
	}
	var iterations int
	if err := json.Unmarshal(document["iterations"], &iterations); err != nil {
		t.Fatal(err)
	}
	if iterations != 2 {
		t.Fatalf("iterations = %d, want 2", iterations)
	}

	manifestBytes, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		WorkloadID string `json:"workload_id"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	var workloadID string
	if err := json.Unmarshal(document["workload_id"], &workloadID); err != nil {
		t.Fatal(err)
	}
	if workloadID != manifest.WorkloadID {
		t.Fatalf("workload_id = %q, want %q", workloadID, manifest.WorkloadID)
	}
	sum := sha256.Sum256(manifestBytes)
	wantHash := hex.EncodeToString(sum[:])
	var manifestSHA string
	if err := json.Unmarshal(document["manifest_sha256"], &manifestSHA); err != nil {
		t.Fatal(err)
	}
	if manifestSHA != wantHash {
		t.Fatalf("manifest_sha256 = %q, want %q", manifestSHA, wantHash)
	}

	var rawCases []map[string]json.RawMessage
	if err := json.Unmarshal(document["cases"], &rawCases); err != nil {
		t.Fatal(err)
	}
	wantCases := []string{
		"get-benign",
		"get-attack",
		"form-benign",
		"form-attack",
		"json-benign",
		"json-attack",
	}
	if len(rawCases) != len(wantCases) {
		t.Fatalf("case count = %d, want %d", len(rawCases), len(wantCases))
	}
	for index, entry := range rawCases {
		if len(entry) != 2 {
			t.Fatalf("case %d fields = %d, want 2", index, len(entry))
		}
		var caseID string
		if err := json.Unmarshal(entry["case_id"], &caseID); err != nil {
			t.Fatal(err)
		}
		if caseID != wantCases[index] {
			t.Fatalf("case %d = %q, want %q", index, caseID, wantCases[index])
		}
		var samples []int64
		if err := json.Unmarshal(entry["samples_ns"], &samples); err != nil {
			t.Fatal(err)
		}
		if len(samples) != 2 {
			t.Fatalf("case %s samples = %d, want 2", caseID, len(samples))
		}
		for sampleIndex, sample := range samples {
			if sample < 0 {
				t.Fatalf("case %s sample %d = %d, want a non-negative duration", caseID, sampleIndex, sample)
			}
		}
	}
}

// TestInvalidIterations rejects missing, zero, negative and oversized counts
// before loading the workload.
func TestInvalidIterations(t *testing.T) {
	root := shippedWorkloadRoot(t)
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "missing"},
		{name: "zero", args: []string{"--iterations", "0"}},
		{name: "negative", args: []string{"--iterations", "-1"}},
		{name: "above bound", args: []string{"--iterations", "1000001"}},
		{name: "not a number", args: []string{"--iterations", "many"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "timing.json")
			args := append([]string{"--workloads", root, "--timing", output}, test.args...)
			err := run(args)
			if err == nil {
				t.Fatal("invalid iterations were accepted")
			}
			if _, statErr := os.Stat(output); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("invalid run wrote %s", output)
			}
		})
	}
}

// TestUnwritableTimingPath fails cleanly when the output directory is missing.
func TestUnwritableTimingPath(t *testing.T) {
	root := shippedWorkloadRoot(t)
	output := filepath.Join(t.TempDir(), "missing", "timing.json")
	err := run([]string{"--workloads", root, "--timing", output, "--iterations", "1"})
	if err == nil || !strings.Contains(err.Error(), "timing output") {
		t.Fatalf("error = %v, want a timing output failure", err)
	}
	if _, statErr := os.Stat(output); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed run wrote %s", output)
	}
}

// TestMissingWorkloadRejected fails when the manifest is absent.
func TestMissingWorkloadRejected(t *testing.T) {
	output := filepath.Join(t.TempDir(), "timing.json")
	err := run([]string{"--workloads", t.TempDir(), "--timing", output, "--iterations", "1"})
	if err == nil {
		t.Fatal("missing workload was accepted")
	}
	if _, statErr := os.Stat(output); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed run wrote %s", output)
	}
}

// TestUnknownFlagRejected rejects flags outside the timing contract.
func TestUnknownFlagRejected(t *testing.T) {
	output := filepath.Join(t.TempDir(), "timing.json")
	err := run([]string{"--timing", output, "--iterations", "1", "--warmup", "1"})
	if err == nil {
		t.Fatal("unknown flag was accepted")
	}
	if _, statErr := os.Stat(output); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed run wrote %s", output)
	}
}
