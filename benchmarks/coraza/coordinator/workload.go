// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	// workloadSchemaVersion is the case schema version shared with the drivers.
	workloadSchemaVersion = 1
	// maxWorkloadFileBytes bounds one manifest or case file read.
	maxWorkloadFileBytes = 16 << 20
)

// manifestFile mirrors the committed workload manifest.
type manifestFile struct {
	SchemaVersion int            `json:"schema_version"`
	WorkloadID    string         `json:"workload_id"`
	Description   string         `json:"description"`
	CaseSchema    string         `json:"case_schema"`
	Cases         []manifestCase `json:"cases"`
}

// manifestCase is one manifest entry.
type manifestCase struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// workloadCase is one validated case file.
type workloadCase struct {
	Path   string
	SHA256 string
	CaseID string
}

// workload is the validated, immutable workload identity.
type workload struct {
	ID             string
	Root           string
	ManifestPath   string
	ManifestSHA256 string
	Cases          []workloadCase
}

// caseIDDocument extracts only the case identifier from a case file. The
// drivers validate the complete case contract.
type caseIDDocument struct {
	CaseID string `json:"case_id"`
}

// loadWorkload reads the manifest, validates every path and hash, and extracts
// the unique case identifiers. Any violation stops the run before drivers or
// the parity command start.
func loadWorkload(root string) (*workload, error) {
	absoluteRoot, err := absolute(root)
	if err != nil {
		return nil, fmt.Errorf("workload directory: %w", err)
	}
	manifestPath := filepath.Join(absoluteRoot, "manifest.json")
	manifestBytes, err := readFileLimited(manifestPath, maxWorkloadFileBytes)
	if err != nil {
		return nil, fmt.Errorf("read workload manifest %s: %w", manifestPath, err)
	}
	var manifest manifestFile
	if err := decodeStrict(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("manifest %s is not valid: %w", manifestPath, err)
	}
	if manifest.SchemaVersion != workloadSchemaVersion {
		return nil, fmt.Errorf("manifest schema_version must be %d, got %d", workloadSchemaVersion, manifest.SchemaVersion)
	}
	if strings.TrimSpace(manifest.WorkloadID) == "" {
		return nil, errors.New("manifest workload_id is empty")
	}
	if strings.TrimSpace(manifest.Description) == "" {
		return nil, errors.New("manifest description is empty")
	}
	if strings.TrimSpace(manifest.CaseSchema) == "" {
		return nil, errors.New("manifest case_schema is empty")
	}
	if len(manifest.Cases) == 0 {
		return nil, errors.New("manifest has no cases")
	}
	seenPaths := make(map[string]struct{}, len(manifest.Cases))
	seenIDs := make(map[string]struct{}, len(manifest.Cases))
	cases := make([]workloadCase, 0, len(manifest.Cases))
	for index, entry := range manifest.Cases {
		context := fmt.Sprintf("manifest case %d", index)
		if err := validateRelativePath(entry.Path); err != nil {
			return nil, fmt.Errorf("%s path: %w", context, err)
		}
		if !isSHA256Hex(entry.SHA256) {
			return nil, fmt.Errorf("%s sha256 is not a lower-case SHA-256 digest", context)
		}
		if _, duplicate := seenPaths[entry.Path]; duplicate {
			return nil, fmt.Errorf("%s repeats case path %q", context, entry.Path)
		}
		seenPaths[entry.Path] = struct{}{}
		casePath := filepath.Join(absoluteRoot, filepath.FromSlash(entry.Path))
		caseBytes, err := readFileLimited(casePath, maxWorkloadFileBytes)
		if err != nil {
			return nil, fmt.Errorf("read case %s: %w", casePath, err)
		}
		actual := sha256Hex(caseBytes)
		if actual != entry.SHA256 {
			return nil, fmt.Errorf("case %s has SHA-256 %s, manifest declares %s", casePath, actual, entry.SHA256)
		}
		var document caseIDDocument
		if err := json.Unmarshal(caseBytes, &document); err != nil {
			return nil, fmt.Errorf("case %s is not valid JSON: %w", casePath, err)
		}
		if strings.TrimSpace(document.CaseID) == "" {
			return nil, fmt.Errorf("case %s has no case_id", casePath)
		}
		if _, duplicate := seenIDs[document.CaseID]; duplicate {
			return nil, fmt.Errorf("duplicate case_id %q", document.CaseID)
		}
		seenIDs[document.CaseID] = struct{}{}
		cases = append(cases, workloadCase{
			Path:   entry.Path,
			SHA256: entry.SHA256,
			CaseID: document.CaseID,
		})
	}
	return &workload{
		ID:             manifest.WorkloadID,
		Root:           absoluteRoot,
		ManifestPath:   manifestPath,
		ManifestSHA256: sha256Hex(manifestBytes),
		Cases:          cases,
	}, nil
}

// validateRelativePath rejects absolute paths and any empty, dot or parent
// component in a manifest path.
func validateRelativePath(text string) error {
	if strings.TrimSpace(text) == "" {
		return errors.New("path is empty")
	}
	if strings.ContainsRune(text, '\x00') {
		return errors.New("path contains a NUL byte")
	}
	if filepath.IsAbs(text) || strings.HasPrefix(text, "/") {
		return fmt.Errorf("path must be relative: %q", text)
	}
	for _, component := range strings.Split(filepath.ToSlash(text), "/") {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("path must not contain empty, . or .. components: %q", text)
		}
	}
	return nil
}

// workloadIdentity captures the workload fields recorded in artifacts.
func workloadIdentityFrom(workload *workload) workloadIdentity {
	return workloadIdentity{
		ID:             workload.ID,
		Root:           workload.Root,
		ManifestPath:   workload.ManifestPath,
		ManifestSHA256: workload.ManifestSHA256,
		CaseCount:      len(workload.Cases),
	}
}

// hasCase reports whether the workload contains caseID.
func (w *workload) hasCase(caseID string) bool {
	for _, entry := range w.Cases {
		if entry.CaseID == caseID {
			return true
		}
	}
	return false
}
