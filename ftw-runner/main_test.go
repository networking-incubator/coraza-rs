// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const oneTestYAML = `meta:
  name: "one"
rule_id: 1001
tests:
  - test_id: 1
    stages:
      - input:
          dest_addr: "127.0.0.1"
          port: 8080
          uri: "/"
          method: "GET"
        output:
          status: 200
      - input:
          uri: "/second"
          method: "GET"
        output:
          status: 200
`

const twoTestYAML = `meta:
  name: "two"
rule_id: 1002
tests:
  - test_id: 1
    stages:
      - input:
          uri: "/a"
          method: "GET"
        output:
          status: 200
  - test_id: 2
    stages:
      - input:
          uri: "/b"
          method: "GET"
        output:
          status: 200
      - input:
          uri: "/c"
          method: "GET"
        output:
          status: 200
`

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestParseMode(t *testing.T) {
	for _, value := range []string{"conformance", "health-only"} {
		if mode, err := parseMode(value); err != nil || string(mode) != value {
			t.Fatalf("parseMode(%q) = %q, %v", value, mode, err)
		}
	}
	if _, err := parseMode(""); err == nil || !strings.Contains(err.Error(), "unknown --mode") {
		t.Fatalf("parseMode(\"\") error = %v, want unknown mode", err)
	}
}

func TestOptionsValidate(t *testing.T) {
	valid := options{
		mode:          modeConformance,
		testDir:       "tests",
		rulesFile:     "rules.conf",
		manifestPath:  "manifest.json",
		expectedRules: -1, expectedFiles: -1, expectedTests: -1, expectedStages: -1,
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("validate() error = %v", err)
	}

	missingDir := valid
	missingDir.testDir = ""
	if err := missingDir.validate(); err == nil || !strings.Contains(err.Error(), "--test-dir is required") {
		t.Fatalf("validate() error = %v, want missing test directory", err)
	}

	missingRules := valid
	missingRules.rulesFile = ""
	if err := missingRules.validate(); err == nil || !strings.Contains(err.Error(), "--rules is required") {
		t.Fatalf("validate() error = %v, want missing rules", err)
	}

	missingManifest := valid
	missingManifest.manifestPath = ""
	if err := missingManifest.validate(); err == nil || !strings.Contains(err.Error(), "--manifest is required") {
		t.Fatalf("validate() error = %v, want missing manifest", err)
	}

	healthOnly := options{
		mode:          modeHealthOnly,
		expectedRules: -1, expectedFiles: -1, expectedTests: -1, expectedStages: -1,
	}
	if err := healthOnly.validate(); err != nil {
		t.Fatalf("health-only validate() error = %v", err)
	}

	healthWithExpectation := healthOnly
	healthWithExpectation.expectedTests = 1
	if err := healthWithExpectation.validate(); err == nil || !strings.Contains(err.Error(), "only valid in conformance mode") {
		t.Fatalf("validate() error = %v, want expectation rejection", err)
	}
}

func TestLoadInventoryRejectsMissingDirectory(t *testing.T) {
	_, err := loadInventory(filepath.Join(t.TempDir(), "missing"))
	if err == nil || !strings.Contains(err.Error(), "test directory") {
		t.Fatalf("loadInventory() error = %v, want missing directory", err)
	}
}

func TestLoadInventoryRejectsEmptyDirectory(t *testing.T) {
	_, err := loadInventory(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "contains no FTW YAML tests") {
		t.Fatalf("loadInventory() error = %v, want empty directory", err)
	}
}

func TestLoadInventoryCountsFilesTestsAndStages(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "a.yaml", oneTestYAML)
	writeTestFile(t, dir, "b.yml", twoTestYAML)
	writeTestFile(t, dir, "notes.txt", "ignored")

	inv, err := loadInventory(dir)
	if err != nil {
		t.Fatalf("loadInventory() error = %v", err)
	}
	if inv.Files != 2 || inv.Tests != 3 || inv.Stages != 5 {
		t.Fatalf("inventory = %+v, want 2 files, 3 tests, 5 stages", inv)
	}
}

func TestLoadInventoryRejectsMalformedFileAmongValidOnes(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "a.yaml", oneTestYAML)
	writeTestFile(t, dir, "z.yaml", "rule_id: 1002\ntests: [\n")

	_, err := loadInventory(dir)
	if err == nil || !strings.Contains(err.Error(), "parse test file") || !strings.Contains(err.Error(), "z.yaml") {
		t.Fatalf("loadInventory() error = %v, want malformed z.yaml", err)
	}
}

func TestLoadInventoryRejectsUnreadableFileAmongValidOnes(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "a.yaml", oneTestYAML)
	if err := os.Symlink(filepath.Join(dir, "missing-target"), filepath.Join(dir, "z.yaml")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, err := loadInventory(dir)
	if err == nil || !strings.Contains(err.Error(), "read test file") || !strings.Contains(err.Error(), "z.yaml") {
		t.Fatalf("loadInventory() error = %v, want unreadable z.yaml", err)
	}
}

func TestSelectFilesLimitsFilesAndReportsAllCountsSeparately(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "a.yaml", oneTestYAML)
	writeTestFile(t, dir, "b.yaml", twoTestYAML)

	inv, err := loadInventory(dir)
	if err != nil {
		t.Fatalf("loadInventory() error = %v", err)
	}
	selected := inv.selectFiles(1)
	if selected.Files != 1 || selected.Tests != 1 || selected.Stages != 2 {
		t.Fatalf("selected = %+v, want 1 file, 1 test, 2 stages", selected)
	}
	if inv.Files != 2 || inv.Tests != 3 || inv.Stages != 5 {
		t.Fatalf("inventory changed: %+v", inv)
	}
	if all := inv.selectFiles(0); all.Files != 2 || all.Tests != 3 || all.Stages != 5 {
		t.Fatalf("selectFiles(0) = %+v, want the full inventory", all)
	}
}

func TestCheckCount(t *testing.T) {
	if err := checkCount("file", -1, 9); err != nil {
		t.Fatalf("checkCount() with unset expectation error = %v", err)
	}
	if err := checkCount("file", 9, 9); err != nil {
		t.Fatalf("checkCount() matching error = %v", err)
	}
	if err := checkCount("file", 8, 9); err == nil || !strings.Contains(err.Error(), "expected 8 file(s), found 9") {
		t.Fatalf("checkCount() mismatch error = %v", err)
	}
}

func TestCheckRunComplete(t *testing.T) {
	if err := checkRunComplete(3, 3); err != nil {
		t.Fatalf("checkRunComplete() error = %v", err)
	}
	if err := checkRunComplete(3, 2); err == nil || !strings.Contains(err.Error(), "incomplete test output") {
		t.Fatalf("checkRunComplete() error = %v, want incomplete output", err)
	}
}

func TestWriteManifestIncludesCountsAndFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	manifest := newResultManifest(options{
		mode:           modeConformance,
		testDir:        "tests",
		expectedRules:  4,
		expectedFiles:  -1,
		expectedTests:  7,
		expectedStages: -1,
	})
	manifest.Counts.Files.Inventory = 2
	manifest.Counts.Files.Selected = 1
	manifest.Counts.Tests.Inventory = 7
	manifest.Results.Run = 1
	manifest.Failures = append(manifest.Failures, "boom")

	if err := writeManifest(path, manifest); err != nil {
		t.Fatalf("writeManifest() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var decoded resultManifest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if decoded.Mode != "conformance" || !decoded.Strict || decoded.OK {
		t.Fatalf("manifest header = %+v", decoded)
	}
	if decoded.Expected.Rules == nil || *decoded.Expected.Rules != 4 {
		t.Fatalf("manifest expected rules = %v", decoded.Expected.Rules)
	}
	if decoded.Expected.Files != nil {
		t.Fatalf("manifest expected files = %v, want null", decoded.Expected.Files)
	}
	if decoded.Counts.Files.Inventory != 2 || decoded.Counts.Files.Selected != 1 {
		t.Fatalf("manifest file counts = %+v", decoded.Counts.Files)
	}
	if len(decoded.Failures) != 1 || decoded.Failures[0] != "boom" {
		t.Fatalf("manifest failures = %v", decoded.Failures)
	}
}

func TestReadServerInventory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.json")
	content := `{"mode":"strict","rules_loaded":12,"skipped_directives":[],"expected_rules":12}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	inventory, err := readServerInventory(path)
	if err != nil {
		t.Fatalf("readServerInventory() error = %v", err)
	}
	if inventory.Mode != "strict" || inventory.RulesLoaded != 12 || len(inventory.SkippedDirectives) != 0 {
		t.Fatalf("inventory = %+v", inventory)
	}
	if inventory.ExpectedRules == nil || *inventory.ExpectedRules != 12 {
		t.Fatalf("inventory expected rules = %v", inventory.ExpectedRules)
	}
}

func TestReadServerInventoryRejectsMissingFile(t *testing.T) {
	_, err := readServerInventory(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil || !strings.Contains(err.Error(), "read") {
		t.Fatalf("readServerInventory() error = %v, want read failure", err)
	}
}

func TestCheckAliveReportsEarlyProcessExit(t *testing.T) {
	done := make(chan struct{})
	close(done)
	server := &Server{done: done}
	if err := server.CheckAlive(); err == nil || !strings.Contains(err.Error(), "exited during the test run") {
		t.Fatalf("CheckAlive() error = %v, want early exit", err)
	}

	server.waitErr = errors.New("exit status 1")
	if err := server.CheckAlive(); err == nil || !strings.Contains(err.Error(), "exit status 1") {
		t.Fatalf("CheckAlive() error = %v, want process error", err)
	}

	running := &Server{done: make(chan struct{})}
	if err := running.CheckAlive(); err != nil {
		t.Fatalf("CheckAlive() on a running process error = %v", err)
	}
}

func TestWaitUntilReadyAcceptsMatchingReadinessToken(t *testing.T) {
	const token = "run-token"
	server := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/coraza-ftw-health/"+token {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, token)
	}))
	port := server.port
	runner := &Server{port: port, readinessToken: token, done: make(chan struct{})}
	if err := runner.WaitUntilReady(time.Second); err != nil {
		t.Fatalf("WaitUntilReady() error = %v", err)
	}
}

func TestWaitUntilReadyRejectsUnrelatedListener(t *testing.T) {
	const token = "run-token"
	server := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readiness" {
			fmt.Fprint(w, token)
			return
		}
		http.Redirect(w, r, "/readiness", http.StatusFound)
	}))
	port := server.port
	runner := &Server{port: port, readinessToken: token, done: make(chan struct{})}
	if err := runner.WaitUntilReady(50 * time.Millisecond); err == nil {
		t.Fatal("WaitUntilReady() accepted an unrelated listener")
	}
}

func TestWaitUntilReadyReportsMissingBackend(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	runner := &Server{port: port, readinessToken: "token", done: make(chan struct{})}
	if err := runner.WaitUntilReady(200 * time.Millisecond); err == nil || !strings.Contains(err.Error(), "did not become ready") {
		t.Fatalf("WaitUntilReady() error = %v, want missing backend", err)
	}
}

func TestWaitUntilReadyReportsExitedProcess(t *testing.T) {
	done := make(chan struct{})
	close(done)
	runner := &Server{done: done}
	if err := runner.WaitUntilReady(time.Second); err == nil || !strings.Contains(err.Error(), "process exited") {
		t.Fatalf("WaitUntilReady() error = %v, want process exit", err)
	}
}

func TestHealthCheckErrorsOnNon200(t *testing.T) {
	server := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	err := testServerHealthAt(server.url, server.client)
	if err == nil || !strings.Contains(err.Error(), "GET /") || !strings.Contains(err.Error(), "503") {
		t.Fatalf("testServerHealthAt() error = %v, want GET / and status 503", err)
	}
}

func TestHealthCheckErrorsOnRedirect(t *testing.T) {
	server := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/redirect-target", http.StatusFound)
	}))

	err := testServerHealthAt(server.url, server.client)
	if err == nil || !strings.Contains(err.Error(), "GET /") || !strings.Contains(err.Error(), "302") {
		t.Fatalf("testServerHealthAt() error = %v, want GET / and status 302", err)
	}
}

func TestHealthCheckPassesOn200(t *testing.T) {
	server := newIPv4TestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err := testServerHealthAt(server.url, server.client); err != nil {
		t.Fatalf("testServerHealthAt() error = %v", err)
	}
}

type localTestServer struct {
	url    string
	port   int
	client *http.Client
}

func newIPv4TestServer(t *testing.T, handler http.Handler) *localTestServer {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on IPv4 loopback: %v", err)
	}
	server := &http.Server{Handler: handler}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() { _ = server.Close() })
	port := listener.Addr().(*net.TCPAddr).Port
	return &localTestServer{
		url:    fmt.Sprintf("http://127.0.0.1:%d", port),
		port:   port,
		client: &http.Client{},
	}
}
