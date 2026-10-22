// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"sort"
)

const (
	// resultSchemaVersion versions run.json and parity.json.
	resultSchemaVersion = 1
	// parityReportSchemaVersion versions the optional per-case report.
	parityReportSchemaVersion = 1
	// timingContractVersion is the driver timing contract documented in
	// benchmarks/coraza/README.md.
	timingContractVersion = "1"
)

// repositoryIdentity is the recorded repository state.
type repositoryIdentity struct {
	Root     string `json:"root"`
	Revision string `json:"revision"`
	Dirty    bool   `json:"dirty"`
}

// workloadIdentity is the recorded workload state.
type workloadIdentity struct {
	ID             string `json:"id"`
	Root           string `json:"root"`
	ManifestPath   string `json:"manifest_path"`
	ManifestSHA256 string `json:"manifest_sha256"`
	CaseCount      int    `json:"case_count"`
}

// commandRecord is one exact command and its working directory.
type commandRecord struct {
	Command string `json:"command"`
	Dir     string `json:"dir"`
}

// commandsRecord is the complete command inventory for a run. Driver commands
// stay absent until the executable is built and resolved.
type commandsRecord struct {
	CheckResolve commandRecord  `json:"checkresolve"`
	Parity       commandRecord  `json:"parity"`
	RustBuild    *commandRecord `json:"rust_build,omitempty"`
	RustDriver   *commandRecord `json:"rust_driver,omitempty"`
	GoBuild      *commandRecord `json:"go_build,omitempty"`
	GoDriver     *commandRecord `json:"go_driver,omitempty"`
}

// identity is the validated run identity recorded before measurements.
type identity struct {
	SchemaVersion     int                `json:"schema_version"`
	Repository        repositoryIdentity `json:"repository"`
	Tools             map[string]string  `json:"tools"`
	Workload          workloadIdentity   `json:"workload"`
	GoEngine          goResolution       `json:"go_engine"`
	ExpectedGoProfile string             `json:"expected_go_profile"`
	GoEnv             map[string]string  `json:"go_env"`
	Commands          commandsRecord     `json:"commands"`
}

// parityRecord is the outcome of the correctness gate.
type parityRecord struct {
	Attempted  bool   `json:"attempted"`
	Command    string `json:"command"`
	Dir        string `json:"dir"`
	ExitCode   int    `json:"exit_code"`
	Passed     bool   `json:"passed"`
	ReportPath string `json:"report,omitempty"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
}

// protocolRecord records the timing protocol parameters.
type protocolRecord struct {
	TimingContract string `json:"timing_contract"`
	Repetitions    int    `json:"repetitions"`
	Iterations     int    `json:"iterations"`
}

// runCaseRecord holds one driver's raw samples for one case.
type runCaseRecord struct {
	CaseID    string  `json:"case_id"`
	SamplesNS []int64 `json:"samples_ns"`
}

// runRecord is one driver invocation.
type runRecord struct {
	Round      int             `json:"round"`
	Position   int             `json:"position"`
	Engine     string          `json:"engine"`
	Command    string          `json:"command"`
	StartedAt  string          `json:"started_at"`
	FinishedAt string          `json:"finished_at"`
	ExitCode   int             `json:"exit_code"`
	RawTiming  string          `json:"raw_timing"`
	Stdout     string          `json:"stdout"`
	Stderr     string          `json:"stderr"`
	Cases      []runCaseRecord `json:"cases"`
}

// caseEngineStats is the aggregate for one engine on one case.
type caseEngineStats struct {
	SampleCount int     `json:"sample_count"`
	MedianNS    float64 `json:"median_ns"`
	MinNS       int64   `json:"min_ns"`
	MaxNS       int64   `json:"max_ns"`
}

// caseResult is the per-case correctness status and, when eligible, ratio.
type caseResult struct {
	CaseID          string                     `json:"case_id"`
	Correctness     string                     `json:"correctness"`
	Reason          string                     `json:"reason,omitempty"`
	Engines         map[string]caseEngineStats `json:"engines"`
	RatioRustOverGo *float64                   `json:"ratio_rust_over_go,omitempty"`
	RatioNote       string                     `json:"ratio_note,omitempty"`
}

// benchResult is the versioned run document.
type benchResult struct {
	SchemaVersion int              `json:"schema_version"`
	Kind          string           `json:"kind"`
	RunID         string           `json:"run_id"`
	StartedAt     string           `json:"started_at"`
	FinishedAt    string           `json:"finished_at"`
	Status        string           `json:"status"`
	Error         string           `json:"error,omitempty"`
	Workload      workloadIdentity `json:"workload"`
	Identity      identity         `json:"identity"`
	Parity        parityRecord     `json:"parity"`
	Protocol      protocolRecord   `json:"protocol"`
	Runs          []runRecord      `json:"runs"`
	Cases         []caseResult     `json:"cases"`
}

// parityDocument is the parity-only artifact.
type parityDocument struct {
	SchemaVersion int              `json:"schema_version"`
	Kind          string           `json:"kind"`
	RunID         string           `json:"run_id"`
	StartedAt     string           `json:"started_at"`
	FinishedAt    string           `json:"finished_at"`
	Status        string           `json:"status"`
	Error         string           `json:"error,omitempty"`
	Workload      workloadIdentity `json:"workload"`
	Identity      identity         `json:"identity"`
	Parity        parityRecord     `json:"parity"`
}

// parityReport is the optional per-case correctness report referenced by
// --parity-report.
type parityReport struct {
	SchemaVersion int                 `json:"schema_version"`
	Cases         []parityReportEntry `json:"cases"`
}

// parityReportEntry is one case's correctness classification.
type parityReportEntry struct {
	CaseID string `json:"case_id"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// runOrder returns the engine order for a zero-based repetition. Even
// repetitions run Rust first; odd repetitions run Go first.
func runOrder(repetition int) []string {
	if repetition%2 == 0 {
		return []string{"rust", "go"}
	}
	return []string{"go", "rust"}
}

// engineStats computes the sample count, median, minimum and maximum over the
// provided nanoseconds. The median of an even count is the mean of the two
// middle samples.
func engineStats(samples []int64) caseEngineStats {
	if len(samples) == 0 {
		return caseEngineStats{}
	}
	sorted := append([]int64(nil), samples...)
	sort.Slice(sorted, func(left, right int) bool { return sorted[left] < sorted[right] })
	middle := len(sorted) / 2
	median := float64(sorted[middle])
	if len(sorted)%2 == 0 {
		median = float64(sorted[middle-1])/2 + float64(sorted[middle])/2
	}
	return caseEngineStats{
		SampleCount: len(sorted),
		MedianNS:    median,
		MinNS:       sorted[0],
		MaxNS:       sorted[len(sorted)-1],
	}
}

// summarizeCases combines the repetitive runs per case. Every manifest case is
// published: a passing case gets a ratio, a divergent or ineligible case keeps
// its statistics but no ratio.
func summarizeCases(workload *workload, runs []runRecord, report *parityReport) []caseResult {
	statuses := make(map[string]parityReportEntry)
	if report != nil {
		for _, entry := range report.Cases {
			statuses[entry.CaseID] = entry
		}
	}
	samples := make(map[string]map[string][]int64, len(workload.Cases))
	for _, run := range runs {
		for _, entry := range run.Cases {
			if samples[entry.CaseID] == nil {
				samples[entry.CaseID] = make(map[string][]int64)
			}
			samples[entry.CaseID][run.Engine] = append(samples[entry.CaseID][run.Engine], entry.SamplesNS...)
		}
	}
	results := make([]caseResult, 0, len(workload.Cases))
	for _, manifestCase := range workload.Cases {
		result := caseResult{
			CaseID:      manifestCase.CaseID,
			Correctness: "passed",
			Engines:     make(map[string]caseEngineStats, 2),
		}
		if report != nil {
			entry, covered := statuses[manifestCase.CaseID]
			if !covered {
				result.Correctness = "ineligible"
				result.Reason = "the parity report does not cover this case"
			} else {
				result.Correctness = entry.Status
				result.Reason = entry.Reason
			}
		}
		for _, engine := range []string{"rust", "go"} {
			result.Engines[engine] = engineStats(samples[manifestCase.CaseID][engine])
		}
		if result.Correctness == "passed" {
			rustStats := result.Engines["rust"]
			goStats := result.Engines["go"]
			switch {
			case rustStats.SampleCount == 0 || goStats.SampleCount == 0:
				result.RatioNote = "missing timing samples"
			case goStats.MedianNS == 0:
				result.RatioNote = "go median is zero"
			default:
				ratio := rustStats.MedianNS / goStats.MedianNS
				result.RatioRustOverGo = &ratio
			}
		} else if result.Reason == "" {
			result.Reason = "the correctness gate did not pass this case"
		}
		results = append(results, result)
	}
	return results
}

// validateParityReport checks the optional report against the workload. Extra,
// duplicate or unknown cases are errors; a missing case is published later as
// ineligible rather than dropped.
func validateParityReport(report *parityReport, workload *workload) error {
	if report.SchemaVersion != parityReportSchemaVersion {
		return fmt.Errorf("parity report schema_version must be %d, got %d", parityReportSchemaVersion, report.SchemaVersion)
	}
	seen := make(map[string]struct{}, len(report.Cases))
	for index, entry := range report.Cases {
		if entry.CaseID == "" {
			return fmt.Errorf("parity report case %d has an empty case_id", index)
		}
		if !workload.hasCase(entry.CaseID) {
			return fmt.Errorf("parity report case %q is not in the workload", entry.CaseID)
		}
		if _, duplicate := seen[entry.CaseID]; duplicate {
			return fmt.Errorf("parity report repeats case %q", entry.CaseID)
		}
		seen[entry.CaseID] = struct{}{}
		switch entry.Status {
		case "passed", "divergent", "ineligible":
		default:
			return fmt.Errorf("parity report case %q has unknown status %q", entry.CaseID, entry.Status)
		}
		if entry.Status != "passed" && entry.Reason == "" {
			return fmt.Errorf("parity report case %q must explain a %s status", entry.CaseID, entry.Status)
		}
	}
	return nil
}
