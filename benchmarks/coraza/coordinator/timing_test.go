// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"math"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunOrderAlternates verifies the paired order discipline.
func TestRunOrderAlternates(t *testing.T) {
	expected := [][]string{
		{"rust", "go"},
		{"go", "rust"},
		{"rust", "go"},
		{"go", "rust"},
	}
	for repetition, want := range expected {
		got := runOrder(repetition)
		if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("repetition %d order is %v, want %v", repetition, got, want)
		}
	}
}

// TestEngineStats covers odd, even, single and empty samples.
func TestEngineStats(t *testing.T) {
	tests := []struct {
		name    string
		samples []int64
		want    caseEngineStats
	}{
		{name: "empty", samples: nil, want: caseEngineStats{}},
		{name: "single", samples: []int64{7}, want: caseEngineStats{SampleCount: 1, MedianNS: 7, MinNS: 7, MaxNS: 7}},
		{name: "odd", samples: []int64{30, 10, 20}, want: caseEngineStats{SampleCount: 3, MedianNS: 20, MinNS: 10, MaxNS: 30}},
		{name: "even", samples: []int64{40, 10, 30, 20}, want: caseEngineStats{SampleCount: 4, MedianNS: 25, MinNS: 10, MaxNS: 40}},
		{name: "duplicates", samples: []int64{5, 5, 5}, want: caseEngineStats{SampleCount: 3, MedianNS: 5, MinNS: 5, MaxNS: 5}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requireEqual(t, engineStats(test.samples), test.want)
		})
	}
}

// TestReadTimingRejectsBadDocuments covers malformed, incomplete and
// identity-inconsistent driver output.
func TestReadTimingRejectsBadDocuments(t *testing.T) {
	_, workload := makeWorkload(t, "case-a", "case-b")
	valid := func() map[string]any {
		document := map[string]any{
			"schema_version":  1,
			"engine":          "rust",
			"workload_id":     workload.ID,
			"manifest_sha256": workload.ManifestSHA256,
			"iterations":      5,
			"cases": []map[string]any{
				{"case_id": "case-a", "samples_ns": []int64{1, 2, 3}},
				{"case_id": "case-b", "samples_ns": []int64{4, 5, 6}},
			},
		}
		return document
	}
	tests := []struct {
		name    string
		mutate  func(document map[string]any)
		rawJSON string
	}{
		{name: "valid"},
		{name: "invalid JSON", rawJSON: "{"},
		{name: "trailing JSON", rawJSON: "{\"schema_version\":1}{}"},
		{name: "unknown field", mutate: func(document map[string]any) { document["extra"] = true }},
		{name: "wrong schema", mutate: func(document map[string]any) { document["schema_version"] = 2 }},
		{name: "wrong engine", mutate: func(document map[string]any) { document["engine"] = "go" }},
		{name: "wrong workload", mutate: func(document map[string]any) { document["workload_id"] = "other" }},
		{name: "wrong manifest hash", mutate: func(document map[string]any) { document["manifest_sha256"] = strings.Repeat("0", 64) }},
		{name: "wrong iterations", mutate: func(document map[string]any) { document["iterations"] = 6 }},
		{
			name: "missing case",
			mutate: func(document map[string]any) {
				document["cases"] = []map[string]any{
					{"case_id": "case-a", "samples_ns": []int64{1}},
				}
			},
		},
		{
			name: "extra case",
			mutate: func(document map[string]any) {
				document["cases"] = []map[string]any{
					{"case_id": "case-a", "samples_ns": []int64{1}},
					{"case_id": "case-b", "samples_ns": []int64{2}},
					{"case_id": "case-c", "samples_ns": []int64{3}},
				}
			},
		},
		{
			name: "duplicate case",
			mutate: func(document map[string]any) {
				document["cases"] = []map[string]any{
					{"case_id": "case-a", "samples_ns": []int64{1}},
					{"case_id": "case-a", "samples_ns": []int64{2}},
				}
			},
		},
		{
			name: "empty samples",
			mutate: func(document map[string]any) {
				document["cases"] = []map[string]any{
					{"case_id": "case-a", "samples_ns": []int64{}},
					{"case_id": "case-b", "samples_ns": []int64{1}},
				}
			},
		},
		{
			name: "negative sample",
			mutate: func(document map[string]any) {
				document["cases"] = []map[string]any{
					{"case_id": "case-a", "samples_ns": []int64{-1}},
					{"case_id": "case-b", "samples_ns": []int64{1}},
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			var data []byte
			var err error
			if test.rawJSON != "" {
				data = []byte(test.rawJSON)
			} else {
				document := valid()
				if test.mutate != nil {
					test.mutate(document)
				}
				data, err = json.Marshal(document)
				if err != nil {
					t.Fatalf("marshal document: %v", err)
				}
			}
			path := writeTestBytes(t, dir, "timing.json", data)
			cases, err := readTiming(path, "rust", workload, 5)
			if test.name == "valid" {
				requireNoError(t, err)
				requireEqual(t, len(cases), 2)
				requireEqual(t, cases[0].CaseID, "case-a")
				requireEqual(t, len(cases[0].SamplesNS), 3)
				return
			}
			requireError(t, err)
		})
	}
}

// TestReadTimingRejectsMissingFile keeps the driver contract explicit.
func TestReadTimingRejectsMissingFile(t *testing.T) {
	_, workload := makeWorkload(t, "case-a")
	missing := filepath.Join(t.TempDir(), "missing.json")
	_, err := readTiming(missing, "rust", workload, 5)
	requireError(t, err)
}

// TestValidateParityReport covers status, coverage and reason rules.
func TestValidateParityReport(t *testing.T) {
	_, workload := makeWorkload(t, "case-a", "case-b")
	tests := []struct {
		name      string
		report    parityReport
		wantError bool
	}{
		{
			name: "valid passed",
			report: parityReport{SchemaVersion: 1, Cases: []parityReportEntry{
				{CaseID: "case-a", Status: "passed"},
				{CaseID: "case-b", Status: "passed"},
			}},
		},
		{
			name: "valid divergent with reason",
			report: parityReport{SchemaVersion: 1, Cases: []parityReportEntry{
				{CaseID: "case-a", Status: "divergent", Reason: "rule set differs"},
			}},
		},
		{
			name:      "wrong schema",
			report:    parityReport{SchemaVersion: 2},
			wantError: true,
		},
		{
			name: "unknown case",
			report: parityReport{SchemaVersion: 1, Cases: []parityReportEntry{
				{CaseID: "case-z", Status: "passed"},
			}},
			wantError: true,
		},
		{
			name: "duplicate case",
			report: parityReport{SchemaVersion: 1, Cases: []parityReportEntry{
				{CaseID: "case-a", Status: "passed"},
				{CaseID: "case-a", Status: "passed"},
			}},
			wantError: true,
		},
		{
			name: "unknown status",
			report: parityReport{SchemaVersion: 1, Cases: []parityReportEntry{
				{CaseID: "case-a", Status: "skipped"},
			}},
			wantError: true,
		},
		{
			name: "divergent without reason",
			report: parityReport{SchemaVersion: 1, Cases: []parityReportEntry{
				{CaseID: "case-a", Status: "divergent"},
			}},
			wantError: true,
		},
		{
			name: "ineligible without reason",
			report: parityReport{SchemaVersion: 1, Cases: []parityReportEntry{
				{CaseID: "case-a", Status: "ineligible"},
			}},
			wantError: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateParityReport(&test.report, workload)
			if test.wantError {
				requireError(t, err)
			} else {
				requireNoError(t, err)
			}
		})
	}
}

// TestSummarizeCasesPublishesEveryCase checks eligibility, reasons and ratios.
func TestSummarizeCasesPublishesEveryCase(t *testing.T) {
	_, workload := makeWorkload(t, "case-a", "case-b", "case-c")
	runs := []runRecord{
		{
			Engine: "rust",
			Cases: []runCaseRecord{
				{CaseID: "case-a", SamplesNS: []int64{100, 200, 300}},
				{CaseID: "case-b", SamplesNS: []int64{10, 20, 30}},
				{CaseID: "case-c", SamplesNS: []int64{1, 2, 3}},
			},
		},
		{
			Engine: "go",
			Cases: []runCaseRecord{
				{CaseID: "case-a", SamplesNS: []int64{50, 60, 70}},
				{CaseID: "case-b", SamplesNS: []int64{5, 5, 5}},
				{CaseID: "case-c", SamplesNS: []int64{1, 1, 1}},
			},
		},
	}
	report := &parityReport{SchemaVersion: 1, Cases: []parityReportEntry{
		{CaseID: "case-a", Status: "passed"},
		{CaseID: "case-b", Status: "divergent", Reason: "matched rules differ"},
	}}
	results := summarizeCases(workload, runs, report)
	requireEqual(t, len(results), 3)
	requireEqual(t, results[0].CaseID, "case-a")
	requireEqual(t, results[0].Correctness, "passed")
	requireEqual(t, results[0].Engines["rust"].SampleCount, 3)
	requireEqual(t, results[0].Engines["rust"].MedianNS, float64(200))
	requireEqual(t, results[0].Engines["go"].MedianNS, float64(60))
	if results[0].RatioRustOverGo == nil {
		t.Fatal("expected a ratio for the passing case")
	}
	if math.Abs(*results[0].RatioRustOverGo-200.0/60.0) > 1e-9 {
		t.Fatalf("unexpected ratio %v", *results[0].RatioRustOverGo)
	}
	requireEqual(t, results[1].Correctness, "divergent")
	requireEqual(t, results[1].Reason, "matched rules differ")
	if results[1].RatioRustOverGo != nil {
		t.Fatal("divergent case must not publish a ratio")
	}
	requireEqual(t, results[2].Correctness, "ineligible")
	if results[2].Reason == "" {
		t.Fatal("uncovered case must explain why it is ineligible")
	}
	if results[2].RatioRustOverGo != nil {
		t.Fatal("ineligible case must not publish a ratio")
	}
}

// TestSummarizeCasesWithoutReportMarksAllPassed covers the default gate result.
func TestSummarizeCasesWithoutReportMarksAllPassed(t *testing.T) {
	_, workload := makeWorkload(t, "case-a")
	runs := []runRecord{
		{Engine: "rust", Cases: []runCaseRecord{{CaseID: "case-a", SamplesNS: []int64{2}}}},
		{Engine: "go", Cases: []runCaseRecord{{CaseID: "case-a", SamplesNS: []int64{1}}}},
	}
	results := summarizeCases(workload, runs, nil)
	requireEqual(t, len(results), 1)
	requireEqual(t, results[0].Correctness, "passed")
	if results[0].RatioRustOverGo == nil || *results[0].RatioRustOverGo != 2 {
		t.Fatalf("unexpected ratio: %v", results[0].RatioRustOverGo)
	}
}
