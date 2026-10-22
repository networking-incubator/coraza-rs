// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// coordinatorEnvKeys are cleared before each test so the developer
// environment cannot change a test's configuration.
var coordinatorEnvKeys = []string{
	"CORAZA_REPO",
	"CORAZA_WORKLOADS",
	"BENCH_OUT",
	"CORAZA_GO_MODULE",
	"CORAZA_CHECKRESOLVE_CMD",
	"CORAZA_GO_PROFILE",
	"CORAZA_PARITY_CMD",
	"CORAZA_PARITY_REPORT",
	"CORAZA_REPETITIONS",
	"CORAZA_ITERATIONS",
	"CORAZA_RUST_BUILD_CMD",
	"CORAZA_RUST_DRIVER_CMD",
	"CORAZA_GO_BUILD_CMD",
	"CORAZA_GO_DRIVER_CMD",
}

// clearCoordinatorEnv isolates a test from ambient coordinator settings.
func clearCoordinatorEnv(t *testing.T) {
	t.Helper()
	for _, key := range coordinatorEnvKeys {
		t.Setenv(key, "")
	}
}

// writeTestFile writes one file and returns its path.
func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create directory for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// writeTestBytes writes one binary file and returns its path.
func writeTestBytes(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create directory for %s: %v", path, err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// writeShellScript writes a POSIX shell script and returns a command string
// that runs it through sh.
func writeShellScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := writeTestFile(t, dir, name, "#!/bin/sh\n"+body+"\n")
	return "sh " + shellQuote(path)
}

// makeWorkload creates a minimal valid workload with the given case IDs.
func makeWorkload(t *testing.T, caseIDs ...string) (string, *workload) {
	t.Helper()
	root := t.TempDir()
	entries := make([]map[string]string, 0, len(caseIDs))
	for _, caseID := range caseIDs {
		data := []byte(fmt.Sprintf("{\"case_id\":%q}\n", caseID))
		path := "cases/" + caseID + ".json"
		writeTestBytes(t, root, path, data)
		entries = append(entries, map[string]string{"path": path, "sha256": sha256Hex(data)})
	}
	manifest := map[string]any{
		"schema_version": 1,
		"workload_id":    "test-workload",
		"description":    "coordinator test workload",
		"case_schema":    "coraza/conformance/corpus-schema.json",
		"cases":          entries,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	writeTestBytes(t, root, "manifest.json", manifestBytes)
	workload, err := loadWorkload(root)
	if err != nil {
		t.Fatalf("load synthetic workload: %v", err)
	}
	return root, workload
}

// makeGoModule creates a minimal isolated Go module directory.
func makeGoModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", "module example.test/coraza-bench\n\ngo 1.26.0\n")
	return dir
}

// checkresolveCommand writes a resolution JSON file and returns a command that
// prints it.
func checkresolveCommand(t *testing.T, dir, profile, revision string, dirty bool) string {
	t.Helper()
	resolution := goResolution{
		Profile:        profile,
		GoBinary:       "/usr/bin/go",
		GoVersion:      "go version test",
		GOWork:         "off",
		GOToolchain:    "local",
		Engine:         goModule{Path: engineModulePath, Version: "v3.8.1"},
		EngineDirty:    dirty,
		EngineRevision: revision,
	}
	if profile == "local" {
		resolution.Engine.Replace = &goModule{Path: "/engines/coraza", Dir: "/engines/coraza"}
		resolution.EngineDir = "/engines/coraza"
	}
	data, err := json.MarshalIndent(resolution, "", "  ")
	if err != nil {
		t.Fatalf("marshal resolution: %v", err)
	}
	path := writeTestBytes(t, dir, "checkresolve.json", data)
	return "cat " + shellQuote(path)
}

// timingDocumentBytes builds a valid timing document for the workload.
func timingDocumentBytes(t *testing.T, engine string, workload *workload, iterations int, samples map[string][]int64) []byte {
	t.Helper()
	document := timingDocument{
		SchemaVersion:  timingSchemaVersion,
		Engine:         engine,
		WorkloadID:     workload.ID,
		ManifestSHA256: workload.ManifestSHA256,
		Iterations:     iterations,
	}
	for _, entry := range workload.Cases {
		document.Cases = append(document.Cases, timingCase{
			CaseID:    entry.CaseID,
			SamplesNS: samples[entry.CaseID],
		})
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal timing document: %v", err)
	}
	return data
}

// writeTimingFile writes a timing document and returns its path.
func writeTimingFile(
	t *testing.T,
	dir string,
	name string,
	engine string,
	workload *workload,
	iterations int,
	samples map[string][]int64,
) string {
	t.Helper()
	return writeTestBytes(t, dir, name, timingDocumentBytes(t, engine, workload, iterations, samples))
}

// writeDriverScript writes a mock driver that records its engine and copies a
// prepared timing document to the --timing path.
func writeDriverScript(t *testing.T, dir, name, engine, timingPath, orderLog string) string {
	t.Helper()
	body := fmt.Sprintf(`printf '%s\n' >> %s
timing=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --timing) timing="$2"; shift 2 ;;
    --workloads|--iterations) shift 2 ;;
    *) shift ;;
  esac
done
if [ -z "$timing" ]; then
  echo "missing --timing" >&2
  exit 9
fi
cp %s "$timing"
`, engine, shellQuote(orderLog), shellQuote(timingPath))
	return writeShellScript(t, dir, name, body)
}

// writeBuildScript writes a mock build command that records one invocation.
func writeBuildScript(t *testing.T, dir, name, label, logPath string) string {
	t.Helper()
	return writeShellScript(t, dir, name, fmt.Sprintf("printf '%s\n' >> %s\n", label, shellQuote(logPath)))
}

// readLines returns the non-empty lines of a file, or an empty slice when the
// file does not exist.
func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read %s: %v", path, err)
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// findRunDir returns the single run directory under outputRoot.
func findRunDir(t *testing.T, outputRoot string) string {
	t.Helper()
	entries, err := os.ReadDir(outputRoot)
	if err != nil {
		t.Fatalf("read output root: %v", err)
	}
	var dirs []string
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, filepath.Join(outputRoot, entry.Name()))
		}
	}
	if len(dirs) != 1 {
		t.Fatalf("expected one run directory under %s, got %v", outputRoot, dirs)
	}
	return dirs[0]
}

// readBenchResult decodes a run.json document.
func readBenchResult(t *testing.T, runDir string) benchResult {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(runDir, "run.json"))
	if err != nil {
		t.Fatalf("read run.json: %v", err)
	}
	var result benchResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode run.json: %v", err)
	}
	return result
}

// readParityDocument decodes a parity.json document.
func readParityDocument(t *testing.T, runDir string) parityDocument {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(runDir, "parity.json"))
	if err != nil {
		t.Fatalf("read parity.json: %v", err)
	}
	var document parityDocument
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode parity.json: %v", err)
	}
	return document
}

// benchArgs builds the flag set for a bench test.
func benchArgs(
	repoRoot, workloadRoot, outputRoot, goModule, checkresolve, parity, rust, goDriver string,
) []string {
	return []string{
		"--repo", repoRoot,
		"--workloads", workloadRoot,
		"--output", outputRoot,
		"--go-module", goModule,
		"--checkresolve-command", checkresolve,
		"--parity-command", parity,
		"--rust-driver-command", rust,
		"--go-driver-command", goDriver,
		"--repetitions", "3",
		"--iterations", "5",
	}
}

// parityArgs builds the flag set for a parity test.
func parityArgs(repoRoot, workloadRoot, outputRoot, goModule, checkresolve, parity string) []string {
	return []string{
		"--repo", repoRoot,
		"--workloads", workloadRoot,
		"--output", outputRoot,
		"--go-module", goModule,
		"--checkresolve-command", checkresolve,
		"--parity-command", parity,
	}
}

// requireNoError fails the test on error.
func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// requireError fails the test when err is nil.
func requireError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// requireEqual fails the test when two values differ.
func requireEqual[T comparable](t *testing.T, got, want T) {
	t.Helper()
	if got != want {
		t.Fatalf("got %v, want %v", got, want)
	}
}
