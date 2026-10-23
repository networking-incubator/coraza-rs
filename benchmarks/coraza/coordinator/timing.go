// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	// timingSchemaVersion versions the driver timing document.
	timingSchemaVersion = 1
	// maxTimingBytes bounds one raw timing document.
	maxTimingBytes = 64 << 20
	// maxSamplesPerCase bounds one case's sample array. The coordinator's
	// maxIterations limit is derived from it, so an accepted --iterations
	// value can never require rejecting the driver's samples.
	maxSamplesPerCase = 1_000_000
)

// timingDocument is the JSON written by a driver in timing mode.
type timingDocument struct {
	SchemaVersion  int          `json:"schema_version"`
	Engine         string       `json:"engine"`
	WorkloadID     string       `json:"workload_id"`
	ManifestSHA256 string       `json:"manifest_sha256"`
	Iterations     int          `json:"iterations"`
	Cases          []timingCase `json:"cases"`
}

// timingCase is one case's raw per-transaction durations.
type timingCase struct {
	CaseID    string  `json:"case_id"`
	SamplesNS []int64 `json:"samples_ns"`
}

// readTiming reads and fully validates one timing document before any
// statistic is computed. Incomplete, malformed or identity-inconsistent files
// are rejected.
func readTiming(path, engine string, workload *workload, iterations int) ([]runCaseRecord, error) {
	data, err := readFileLimited(path, maxTimingBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("driver did not write timing output %s", path)
		}
		return nil, err
	}
	var document timingDocument
	if err := decodeStrict(data, &document); err != nil {
		return nil, fmt.Errorf("timing output %s is not valid: %w", path, err)
	}
	if document.SchemaVersion != timingSchemaVersion {
		return nil, fmt.Errorf(
			"timing output %s schema_version is %d, want %d",
			path, document.SchemaVersion, timingSchemaVersion,
		)
	}
	if document.Engine != engine {
		return nil, fmt.Errorf("timing output %s reports engine %q, want %q", path, document.Engine, engine)
	}
	if document.WorkloadID != workload.ID {
		return nil, fmt.Errorf(
			"timing output %s reports workload %q, want %q",
			path, document.WorkloadID, workload.ID,
		)
	}
	if document.ManifestSHA256 != workload.ManifestSHA256 {
		return nil, fmt.Errorf("timing output %s reports a different manifest hash", path)
	}
	if document.Iterations != iterations {
		return nil, fmt.Errorf(
			"timing output %s reports %d iterations, requested %d",
			path, document.Iterations, iterations,
		)
	}
	if len(document.Cases) == 0 {
		return nil, fmt.Errorf("timing output %s has no cases", path)
	}
	byID := make(map[string][]int64, len(document.Cases))
	for index, entry := range document.Cases {
		if strings.TrimSpace(entry.CaseID) == "" {
			return nil, fmt.Errorf("timing output %s case %d has an empty case_id", path, index)
		}
		if !workload.hasCase(entry.CaseID) {
			return nil, fmt.Errorf("timing output %s has unknown case %q", path, entry.CaseID)
		}
		if _, duplicate := byID[entry.CaseID]; duplicate {
			return nil, fmt.Errorf("timing output %s repeats case %q", path, entry.CaseID)
		}
		if len(entry.SamplesNS) == 0 {
			return nil, fmt.Errorf("timing output %s case %q has no samples", path, entry.CaseID)
		}
		if len(entry.SamplesNS) > maxSamplesPerCase {
			return nil, fmt.Errorf(
				"timing output %s case %q has more than %d samples",
				path, entry.CaseID, maxSamplesPerCase,
			)
		}
		for _, sample := range entry.SamplesNS {
			if sample < 0 {
				return nil, fmt.Errorf("timing output %s case %q has a negative duration", path, entry.CaseID)
			}
		}
		byID[entry.CaseID] = entry.SamplesNS
	}
	cases := make([]runCaseRecord, 0, len(workload.Cases))
	for _, manifestCase := range workload.Cases {
		samples, present := byID[manifestCase.CaseID]
		if !present {
			return nil, fmt.Errorf("timing output %s is missing case %q", path, manifestCase.CaseID)
		}
		cases = append(cases, runCaseRecord{CaseID: manifestCase.CaseID, SamplesNS: samples})
	}
	return cases, nil
}

// loadParityReport reads the optional report. A missing path yields no report.
func loadParityReport(path string, workload *workload) (*parityReport, error) {
	if path == "" {
		return nil, nil
	}
	data, err := readFileLimited(path, maxWorkloadFileBytes)
	if err != nil {
		return nil, fmt.Errorf("read parity report %s: %w", path, err)
	}
	var report parityReport
	if err := decodeStrict(data, &report); err != nil {
		return nil, fmt.Errorf("parity report %s is not valid: %w", path, err)
	}
	if err := validateParityReport(&report, workload); err != nil {
		return nil, err
	}
	return &report, nil
}
