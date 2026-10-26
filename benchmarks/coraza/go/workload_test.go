// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package bench

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shippedWorkloadRoot returns the workload directory shipped next to the Go
// module.
func shippedWorkloadRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "workloads"))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// minimalCase returns a case that satisfies the canonical lifecycle.
func minimalCase() map[string]any {
	return map[string]any{
		"schema_version": 1,
		"case_id":        "minimal",
		"fixture_sha256": sha256Hex([]byte("ok")),
		"reference": map[string]any{
			"profile":     "test",
			"go_commit":   "d9cc9befc2721fd217ce1660a0e91aca1157221d",
			"rust_commit": "e078282328dce075ad8b421bf052aa1f7190c6ec",
		},
		"connection": map[string]any{
			"remote_addr": "203.0.113.7",
			"remote_port": 50000,
			"local_addr":  "192.0.2.10",
			"local_port":  8080,
			"tls":         false,
			"tls_version": nil,
		},
		"request": map[string]any{
			"method":   "GET",
			"uri":      map[string]any{"base64": base64.StdEncoding.EncodeToString([]byte("/"))},
			"protocol": "HTTP/1.1",
			"headers":  []any{},
			"body":     map[string]any{"base64": ""},
			"chunks":   []any{},
		},
		"response": map[string]any{
			"status":   200,
			"protocol": "HTTP/1.1",
			"headers":  []any{},
			"body":     map[string]any{"base64": base64.StdEncoding.EncodeToString([]byte("ok"))},
			"chunks":   []any{map[string]any{"offset": 0, "length": 2}},
		},
		"processor": map[string]any{
			"sec_lang":                map[string]any{"utf8": "SecRuleEngine On\n"},
			"request_body_processor":  "auto",
			"response_body_processor": "auto",
			"config":                  map[string]any{},
		},
		"phase_calls": []any{
			map[string]any{"call": "process_connection", "phase": 1},
			map[string]any{"call": "process_uri", "phase": 1},
			map[string]any{"call": "process_request_headers", "phase": 1},
			map[string]any{"call": "process_request_body", "phase": 2},
			map[string]any{"call": "process_response_headers", "phase": 3},
			map[string]any{"call": "append_response_body", "phase": 4, "chunk_index": 0},
			map[string]any{"call": "process_response_body", "phase": 4},
			map[string]any{"call": "process_logging", "phase": 5},
		},
		"expected": map[string]any{
			"matches":       []any{},
			"interruptions": []any{},
			"captures":      []any{},
			"scores":        map[string]any{},
			"flags":         map[string]any{},
			"collections":   []any{},
			"audit":         map[string]any{"required": false, "parts": "", "entries": 0},
		},
		"normalize": []any{"timestamps"},
	}
}

// parseCaseForTest marshals and parses a synthetic case.
func parseCaseForTest(t *testing.T, value any, corpusRoot string) (*workloadCase, error) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return parseCaseBytes(data, corpusRoot)
}

// TestLoadShippedWorkload lists the common subset in manifest order.
func TestLoadShippedWorkload(t *testing.T) {
	cases, err := LoadWorkload(shippedWorkloadRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer closePrepared(t, cases)
	ids := make([]string, 0, len(cases))
	for _, prepared := range cases {
		ids = append(ids, prepared.ID)
	}
	want := []string{"get-benign", "get-attack", "form-benign", "form-attack", "json-benign", "json-attack"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("case ids = %v, want %v", ids, want)
	}
}

// TestRunShippedWorkloadMatchesExpected runs every shipped case through the Go
// lifecycle and compares the observable outcome with its expected block.
func TestRunShippedWorkloadMatchesExpected(t *testing.T) {
	cases, err := LoadWorkload(shippedWorkloadRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer closePrepared(t, cases)
	for _, prepared := range cases {
		outcome, err := RunCase(prepared)
		if err != nil {
			t.Fatalf("case %s: %v", prepared.ID, err)
		}
		if err := CheckExpected(prepared, outcome); err != nil {
			t.Fatalf("case %s: %v", prepared.ID, err)
		}
	}
}

// closePrepared releases every compiled policy after a test.
func closePrepared(t *testing.T, cases []*PreparedCase) {
	t.Helper()
	for _, prepared := range cases {
		if err := prepared.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// TestTamperedManifestHashRejected rejects a manifest whose case hash differs.
func TestTamperedManifestHashRejected(t *testing.T) {
	temporary := t.TempDir()
	casePath := filepath.Join(temporary, "cases", "get-benign.json")
	if err := os.MkdirAll(filepath.Dir(casePath), 0o755); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(shippedWorkloadRoot(t), "cases", "get-benign.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(casePath, source, 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{
		"schema_version": 1,
		"workload_id":    "tampered",
		"description":    "tampered manifest",
		"case_schema":    "coraza/conformance/corpus-schema.json",
		"cases": []any{
			map[string]any{"path": "cases/get-benign.json", "sha256": strings.Repeat("0", 64)},
		},
	}
	writeManifest(t, temporary, manifest)
	_, err = LoadWorkload(temporary)
	if err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("error = %v, want a hash mismatch", err)
	}
}

// TestDuplicateCaseIDRejected rejects two case files that declare one case_id.
func TestDuplicateCaseIDRejected(t *testing.T) {
	temporary := t.TempDir()
	if err := os.MkdirAll(filepath.Join(temporary, "cases"), 0o755); err != nil {
		t.Fatal(err)
	}
	value := minimalCase()
	value["case_id"] = "duplicate"
	source, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]any, 0, 2)
	for _, name := range []string{"a.json", "b.json"} {
		if err := os.WriteFile(filepath.Join(temporary, "cases", name), source, 0o644); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, map[string]any{
			"path":   "cases/" + name,
			"sha256": sha256Hex(source),
		})
	}
	writeManifest(t, temporary, map[string]any{
		"schema_version": 1,
		"workload_id":    "duplicate",
		"description":    "duplicate case id manifest",
		"case_schema":    "coraza/conformance/corpus-schema.json",
		"cases":          entries,
	})
	_, err = LoadWorkload(temporary)
	if err == nil || !strings.Contains(err.Error(), `duplicate case id "duplicate"`) {
		t.Fatalf("error = %v, want duplicate case id rejection", err)
	}
	for _, name := range []string{"cases/a.json", "cases/b.json"} {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("error = %v, want %s", err, name)
		}
	}
}

// TestCasePathTraversalRejected rejects parent traversal in case paths.
func TestCasePathTraversalRejected(t *testing.T) {
	temporary := t.TempDir()
	writeManifest(t, temporary, map[string]any{
		"schema_version": 1,
		"workload_id":    "traversal",
		"description":    "traversal manifest",
		"case_schema":    "coraza/conformance/corpus-schema.json",
		"cases": []any{
			map[string]any{"path": "../get-benign.json", "sha256": strings.Repeat("0", 64)},
		},
	})
	_, err := LoadWorkload(temporary)
	if err == nil || !strings.Contains(err.Error(), ".. components") {
		t.Fatalf("error = %v, want parent traversal rejection", err)
	}
}

// TestOptionalTLSVersionMayBeAbsent accepts a connection without tls_version.
func TestOptionalTLSVersionMayBeAbsent(t *testing.T) {
	value := minimalCase()
	delete(value["connection"].(map[string]any), "tls_version")
	if _, err := parseCaseForTest(t, value, "."); err != nil {
		t.Fatalf("absent tls_version must be accepted: %v", err)
	}
}

// TestInvalidBase64Rejected rejects malformed inline bytes.
func TestInvalidBase64Rejected(t *testing.T) {
	value := minimalCase()
	value["request"].(map[string]any)["body"] = map[string]any{"base64": "not base64!"}
	_, err := parseCaseForTest(t, value, ".")
	if err == nil || !strings.Contains(err.Error(), "invalid base64") {
		t.Fatalf("error = %v, want invalid base64", err)
	}
}

// TestEmptyExpectedCaptureRejected rejects an expectation the observation side
// cannot distinguish from an absent capture.
func TestEmptyExpectedCaptureRejected(t *testing.T) {
	value := minimalCase()
	value["expected"].(map[string]any)["captures"] = []any{
		map[string]any{"index": 0, "value": map[string]any{"base64": ""}},
	}
	_, err := parseCaseForTest(t, value, ".")
	if err == nil || !strings.Contains(err.Error(), "empty capture") {
		t.Fatalf("error = %v, want empty capture rejection", err)
	}
}

// TestChunkGapRejected rejects chunks that do not cover the body.
func TestChunkGapRejected(t *testing.T) {
	value := minimalCase()
	value["response"].(map[string]any)["chunks"] = []any{map[string]any{"offset": 0, "length": 1}}
	_, err := parseCaseForTest(t, value, ".")
	if err == nil || !strings.Contains(err.Error(), "chunks cover") {
		t.Fatalf("error = %v, want chunk coverage rejection", err)
	}
}

// TestWrongSchemaVersionRejected rejects unknown schema versions.
func TestWrongSchemaVersionRejected(t *testing.T) {
	value := minimalCase()
	value["schema_version"] = 2
	_, err := parseCaseForTest(t, value, ".")
	if err == nil || !strings.Contains(err.Error(), "schema_version") {
		t.Fatalf("error = %v, want schema version rejection", err)
	}
}

// TestUnknownFieldRejected rejects fields the schema does not declare.
func TestUnknownFieldRejected(t *testing.T) {
	value := minimalCase()
	value["unexpected"] = true
	_, err := parseCaseForTest(t, value, ".")
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error = %v, want unknown field rejection", err)
	}
}

// TestFixtureRangesAndHashesValidated mirrors the Rust fixture checks.
func TestFixtureRangesAndHashesValidated(t *testing.T) {
	temporary := t.TempDir()
	payload := []byte("0123456789")
	if err := os.WriteFile(filepath.Join(temporary, "payload.bin"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	hash := sha256Hex(payload)
	value := minimalCase()
	request := value["request"].(map[string]any)
	request["body"] = map[string]any{
		"fixture": "payload.bin",
		"sha256":  hash,
		"offset":  2,
		"length":  5,
	}
	request["chunks"] = []any{
		map[string]any{"offset": 0, "length": 2},
		map[string]any{"offset": 2, "length": 3},
	}
	value["phase_calls"] = []any{
		map[string]any{"call": "process_connection", "phase": 1},
		map[string]any{"call": "process_uri", "phase": 1},
		map[string]any{"call": "process_request_headers", "phase": 1},
		map[string]any{"call": "append_request_body", "phase": 2, "chunk_index": 0},
		map[string]any{"call": "append_request_body", "phase": 2, "chunk_index": 1},
		map[string]any{"call": "process_request_body", "phase": 2},
		map[string]any{"call": "process_response_headers", "phase": 3},
		map[string]any{"call": "append_response_body", "phase": 4, "chunk_index": 0},
		map[string]any{"call": "process_response_body", "phase": 4},
		map[string]any{"call": "process_logging", "phase": 5},
	}
	// The schema pins fixture_sha256 to the fixture file, not the range.
	value["fixture_sha256"] = hash
	parsed, err := parseCaseForTest(t, value, temporary)
	if err != nil {
		t.Fatal(err)
	}
	if string(parsed.request.body) != "23456" {
		t.Fatalf("fixture range bytes = %q, want %q", parsed.request.body, "23456")
	}
	if parsed.request.chunkCount != 2 {
		t.Fatalf("chunk count = %d, want 2", parsed.request.chunkCount)
	}

	request["body"].(map[string]any)["offset"] = 8
	request["body"].(map[string]any)["length"] = 5
	_, err = parseCaseForTest(t, value, temporary)
	if err == nil || !strings.Contains(err.Error(), "past the end") {
		t.Fatalf("error = %v, want a range past the fixture", err)
	}

	tampered := minimalCase()
	tamperedRequest := tampered["request"].(map[string]any)
	tamperedRequest["body"] = map[string]any{
		"fixture": "payload.bin",
		"sha256":  strings.Repeat("0", 64),
		"offset":  0,
		"length":  2,
	}
	tamperedRequest["chunks"] = []any{map[string]any{"offset": 0, "length": 2}}
	tampered["fixture_sha256"] = strings.Repeat("0", 64)
	_, err = parseCaseForTest(t, tampered, temporary)
	if err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("error = %v, want a fixture hash mismatch", err)
	}
}

// TestCaseRequiresCanonicalLifecycle rejects a reordered or incomplete lifecycle.
func TestCaseRequiresCanonicalLifecycle(t *testing.T) {
	value := minimalCase()
	value["phase_calls"] = []any{
		map[string]any{"call": "process_connection", "phase": 1},
		map[string]any{"call": "process_uri", "phase": 1},
		map[string]any{"call": "process_logging", "phase": 5},
	}
	_, err := parseCaseForTest(t, value, ".")
	if err == nil || !strings.Contains(err.Error(), "canonical lifecycle") {
		t.Fatalf("error = %v, want canonical lifecycle rejection", err)
	}
}

// writeManifest writes a manifest into a test directory.
func writeManifest(t *testing.T, root string, manifest map[string]any) {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}
