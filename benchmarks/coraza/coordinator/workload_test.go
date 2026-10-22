// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadWorkloadAcceptsValidManifest checks the happy path and identity
// fields used by the result document.
func TestLoadWorkloadAcceptsValidManifest(t *testing.T) {
	clearCoordinatorEnv(t)
	root, workload := makeWorkload(t, "case-a", "case-b")
	requireEqual(t, workload.ID, "test-workload")
	requireEqual(t, workload.Root, root)
	requireEqual(t, len(workload.Cases), 2)
	requireEqual(t, workload.Cases[0].CaseID, "case-a")
	requireEqual(t, workload.Cases[1].CaseID, "case-b")
	requireEqual(t, len(workload.ManifestSHA256), 64)
	requireEqual(t, workloadIdentityFrom(workload).ManifestSHA256, workload.ManifestSHA256)
}

// TestLoadWorkloadRejectsInvalidInputs covers manifest, case and hash
// violations that must stop a run before any driver starts.
func TestLoadWorkloadRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, root string, workload *workload)
	}{
		{
			name: "missing manifest",
			mutate: func(t *testing.T, root string, _ *workload) {
				t.Helper()
				if err := os.Remove(filepath.Join(root, "manifest.json")); err != nil {
					t.Fatalf("remove manifest: %v", err)
				}
			},
		},
		{
			name: "invalid manifest JSON",
			mutate: func(t *testing.T, root string, _ *workload) {
				t.Helper()
				writeTestFile(t, root, "manifest.json", "{")
			},
		},
		{
			name: "zero cases",
			mutate: func(t *testing.T, root string, workload *workload) {
				t.Helper()
				writeManifest(t, root, workload, []map[string]string{})
			},
		},
		{
			name: "case hash mismatch",
			mutate: func(t *testing.T, root string, _ *workload) {
				t.Helper()
				writeTestFile(t, root, "cases/case-a.json", "{\"case_id\":\"case-a\",\"changed\":true}\n")
			},
		},
		{
			name: "duplicate case path",
			mutate: func(t *testing.T, root string, workload *workload) {
				t.Helper()
				entry := map[string]string{"path": "cases/case-a.json", "sha256": sha256Hex([]byte("{\"case_id\":\"case-a\"}\n"))}
				writeManifest(t, root, workload, []map[string]string{entry, entry})
			},
		},
		{
			name: "absolute case path",
			mutate: func(t *testing.T, root string, workload *workload) {
				t.Helper()
				entry := map[string]string{"path": "/tmp/case.json", "sha256": sha256Hex([]byte("x"))}
				writeManifest(t, root, workload, []map[string]string{entry})
			},
		},
		{
			name: "parent traversal",
			mutate: func(t *testing.T, root string, workload *workload) {
				t.Helper()
				entry := map[string]string{"path": "../case.json", "sha256": sha256Hex([]byte("x"))}
				writeManifest(t, root, workload, []map[string]string{entry})
			},
		},
		{
			name: "malformed hash",
			mutate: func(t *testing.T, root string, workload *workload) {
				t.Helper()
				entry := map[string]string{"path": "cases/case-a.json", "sha256": "abc"}
				writeManifest(t, root, workload, []map[string]string{entry})
			},
		},
		{
			name: "missing case file",
			mutate: func(t *testing.T, root string, workload *workload) {
				t.Helper()
				if err := os.Remove(filepath.Join(root, "cases", "case-a.json")); err != nil {
					t.Fatalf("remove case: %v", err)
				}
				writeManifest(t, root, workload, []map[string]string{
					{"path": "cases/case-a.json", "sha256": strings.Repeat("0", 64)},
				})
			},
		},
		{
			name: "duplicate case id",
			mutate: func(t *testing.T, root string, workload *workload) {
				t.Helper()
				first := []byte("{\"case_id\":\"same\"}\n")
				second := []byte("{\"case_id\":\"same\",\"other\":1}\n")
				writeTestBytes(t, root, "cases/one.json", first)
				writeTestBytes(t, root, "cases/two.json", second)
				writeManifest(t, root, workload, []map[string]string{
					{"path": "cases/one.json", "sha256": sha256Hex(first)},
					{"path": "cases/two.json", "sha256": sha256Hex(second)},
				})
			},
		},
		{
			name: "missing case id",
			mutate: func(t *testing.T, root string, workload *workload) {
				t.Helper()
				data := []byte("{}\n")
				writeTestBytes(t, root, "cases/no-id.json", data)
				writeManifest(t, root, workload, []map[string]string{
					{"path": "cases/no-id.json", "sha256": sha256Hex(data)},
				})
			},
		},
		{
			name: "unknown manifest field",
			mutate: func(t *testing.T, root string, workload *workload) {
				t.Helper()
				manifest := map[string]any{
					"schema_version": 1,
					"workload_id":    workload.ID,
					"description":    "test",
					"case_schema":    "schema.json",
					"cases":          []map[string]string{},
					"unexpected":     true,
				}
				writeManifestValue(t, root, manifest)
			},
		},
		{
			name: "wrong schema version",
			mutate: func(t *testing.T, root string, workload *workload) {
				t.Helper()
				manifest := map[string]any{
					"schema_version": 2,
					"workload_id":    workload.ID,
					"description":    "test",
					"case_schema":    "schema.json",
					"cases":          []map[string]string{},
				}
				writeManifestValue(t, root, manifest)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearCoordinatorEnv(t)
			root, workload := makeWorkload(t, "case-a", "case-b")
			test.mutate(t, root, workload)
			_, err := loadWorkload(root)
			requireError(t, err)
		})
	}
}

// writeManifest rewrites the manifest with the given entries.
func writeManifest(t *testing.T, root string, workload *workload, entries []map[string]string) {
	t.Helper()
	writeManifestValue(t, root, map[string]any{
		"schema_version": 1,
		"workload_id":    workload.ID,
		"description":    "coordinator test workload",
		"case_schema":    "coraza/conformance/corpus-schema.json",
		"cases":          entries,
	})
}

// writeManifestValue marshals and writes one manifest value.
func writeManifestValue(t *testing.T, root string, manifest map[string]any) {
	t.Helper()
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	writeTestBytes(t, root, "manifest.json", data)
}

// TestValidateRelativePath covers path contract edge cases.
func TestValidateRelativePath(t *testing.T) {
	for _, valid := range []string{"cases/a.json", "a/b/c.json"} {
		if err := validateRelativePath(valid); err != nil {
			t.Fatalf("expected %q to be valid: %v", valid, err)
		}
	}
	for _, invalid := range []string{"", ".", "..", "/abs.json", "cases/../x.json", "cases//x.json", "cases/./x.json"} {
		if err := validateRelativePath(invalid); err == nil {
			t.Fatalf("expected %q to be rejected", invalid)
		}
	}
}
