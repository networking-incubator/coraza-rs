// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

// Package main provides a test harness for running go-ftw tests against coraza-rs
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/coreruleset/go-ftw/v2/config"
	"github.com/coreruleset/go-ftw/v2/output"
	"github.com/coreruleset/go-ftw/v2/runner"
	"github.com/coreruleset/go-ftw/v2/test"
	"github.com/rs/zerolog"
)

const (
	serverPort       = 8080
	serverBinaryPath = "../target/release/examples/ftw_server_async"
)

type runMode string

const (
	// modeConformance requires a complete, strict FTW inventory and run.
	modeConformance runMode = "conformance"
	// modeHealthOnly only checks that the server answers basic requests.
	modeHealthOnly runMode = "health-only"
)

var serverLogfile string

func parseMode(value string) (runMode, error) {
	switch mode := runMode(value); mode {
	case modeConformance, modeHealthOnly:
		return mode, nil
	default:
		return "", fmt.Errorf("unknown --mode %q (want %q or %q)", value, modeConformance, modeHealthOnly)
	}
}

// options holds the runner configuration after command-line validation.
type options struct {
	mode           runMode
	rulesFile      string
	testDir        string
	maxTests       int
	failedOut      string
	manifestPath   string
	expectedRules  int
	expectedFiles  int
	expectedTests  int
	expectedStages int
}

// validate rejects combinations that could hide missing coverage.
func (o options) validate() error {
	if o.mode == modeConformance {
		if o.testDir == "" {
			return errors.New("--test-dir is required in conformance mode")
		}
		if o.rulesFile == "" {
			return errors.New("--rules is required in conformance mode")
		}
		if o.manifestPath == "" {
			return errors.New("--manifest is required in conformance mode")
		}
		return nil
	}
	if o.expectedRules >= 0 || o.expectedFiles >= 0 || o.expectedTests >= 0 || o.expectedStages >= 0 {
		return errors.New("--expected-* counts are only valid in conformance mode")
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	// Parse command-line flags
	rulesFile := flag.String("rules", "", "Path to CRS rules file (e.g., crs-test.conf)")
	modeFlag := flag.String("mode", string(modeConformance), "Run mode: conformance or health-only")
	maxTests := flag.Int("max-tests", 0, "Maximum number of test files to run (0 = all files)")
	testDir := flag.String("test-dir", "", "Directory searched recursively for FTW tests (required in conformance mode)")
	failedOut := flag.String("failed-out", "", "File to write the IDs of the failed tests to, one per line")
	manifestPath := flag.String("manifest", "ftw-result.json", "Path for the machine-readable conformance result manifest")
	expectedRules := flag.Int("expected-rules", -1, "Expected number of loaded WAF rules (-1 = not checked)")
	expectedFiles := flag.Int("expected-files", -1, "Expected number of FTW test files (-1 = not checked)")
	expectedTests := flag.Int("expected-tests", -1, "Expected number of FTW test cases (-1 = not checked)")
	expectedStages := flag.Int("expected-stages", -1, "Expected number of FTW stages (-1 = not checked)")
	flag.Parse()

	mode, err := parseMode(*modeFlag)
	if err != nil {
		return err
	}
	opts := options{
		mode:           mode,
		rulesFile:      *rulesFile,
		testDir:        *testDir,
		maxTests:       *maxTests,
		failedOut:      *failedOut,
		manifestPath:   *manifestPath,
		expectedRules:  *expectedRules,
		expectedFiles:  *expectedFiles,
		expectedTests:  *expectedTests,
		expectedStages: *expectedStages,
	}
	if err := opts.validate(); err != nil {
		return err
	}

	fmt.Println("Coraza-RS FTW test runner")

	if opts.mode == modeHealthOnly {
		return runHealthOnly(opts)
	}
	return runConformance(opts)
}

// runHealthOnly performs only the explicitly requested basic health checks.
func runHealthOnly(opts options) error {
	server, cleanup, err := startServer(opts)
	if err != nil {
		return err
	}
	defer cleanup()

	fmt.Printf("Server ready on http://localhost:%d\n\n", server.port)
	fmt.Println("Running in explicitly selected health-only mode; no FTW coverage is asserted")
	return testServerHealth()
}

// startServer builds and starts the Rust server, preserving token-based readiness.
func startServer(opts options) (*Server, func(), error) {
	if _, err := os.Stat(serverBinaryPath); err != nil {
		return nil, nil, fmt.Errorf("server binary not found at %s; build it with cargo build --release -p coraza --example ftw_server_async --features async-server: %w", serverBinaryPath, err)
	}
	fmt.Printf("Found server binary: %s\n", serverBinaryPath)

	auditDir, err := os.MkdirTemp("", "coraza-ftw-audit-")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create audit directory: %w", err)
	}
	serverLogfile = filepath.Join(auditDir, "audit.log")
	cleanupDir := func() {
		if err := os.RemoveAll(auditDir); err != nil {
			fmt.Fprintf(os.Stderr, "failed to remove audit directory %s: %v\n", auditDir, err)
		}
	}

	fmt.Println("Starting FTW server...")
	server := &Server{
		port:          serverPort,
		logfile:       serverLogfile,
		rulesFile:     opts.rulesFile,
		strict:        opts.mode == modeConformance,
		expectedRules: opts.expectedRules,
	}
	if opts.mode == modeConformance {
		server.inventoryPath = filepath.Join(auditDir, "server-inventory.json")
	}

	if err := server.Start(); err != nil {
		cleanupDir()
		return nil, nil, fmt.Errorf("failed to start server: %w", err)
	}

	fmt.Println("Waiting for server to be ready...")
	if err := server.WaitUntilReady(30 * time.Second); err != nil {
		server.Stop()
		cleanupDir()
		return nil, nil, err
	}
	return server, func() {
		server.Stop()
		cleanupDir()
	}, nil
}

// Server represents the Rust FTW server process
type Server struct {
	cmd            *exec.Cmd
	port           int
	logfile        string
	rulesFile      string
	readinessToken string
	strict         bool
	expectedRules  int
	inventoryPath  string
	done           chan struct{}
	waitErr        error
}

// Start starts the server process
func (s *Server) Start() error {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return fmt.Errorf("failed to generate server readiness token: %w", err)
	}
	s.readinessToken = hex.EncodeToString(token)

	args := []string{
		"--port", fmt.Sprintf("%d", s.port),
		"--logfile", s.logfile,
		"--readiness-token", s.readinessToken,
	}

	if s.rulesFile != "" {
		args = append(args, "--rules", s.rulesFile)
	}
	if s.strict {
		args = append(args, "--strict")
	}
	if s.expectedRules >= 0 {
		args = append(args, "--expected-rules", strconv.Itoa(s.expectedRules))
	}
	if s.inventoryPath != "" {
		args = append(args, "--inventory-file", s.inventoryPath)
	}

	s.cmd = exec.Command(serverBinaryPath, args...)
	s.cmd.Stdout = os.Stdout
	s.cmd.Stderr = os.Stderr

	if err := s.cmd.Start(); err != nil {
		return err
	}
	s.done = make(chan struct{})
	go func() {
		s.waitErr = s.cmd.Wait()
		close(s.done)
	}()
	return nil
}

// Stop stops the server process
func (s *Server) Stop() {
	if s.cmd != nil && s.cmd.Process != nil {
		fmt.Println("\nStopping server...")
		select {
		case <-s.done:
		default:
			if err := s.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				fmt.Fprintf(os.Stderr, "failed to stop FTW server: %v\n", err)
			}
			<-s.done
		}
		s.cmd = nil
	}
}

// CheckAlive reports an early process exit after readiness was observed.
func (s *Server) CheckAlive() error {
	if s.done == nil {
		return nil
	}
	select {
	case <-s.done:
		if s.waitErr != nil {
			return fmt.Errorf("server process exited during the test run: %w", s.waitErr)
		}
		return errors.New("server process exited during the test run")
	default:
		return nil
	}
}

// WaitUntilReady polls until this server responds or the process exits.
func (s *Server) WaitUntilReady(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return s.exitedBeforeReady()
		default:
		}
		if s.IsHealthy(ctx) {
			select {
			case <-s.done:
				return s.exitedBeforeReady()
			default:
				return nil
			}
		}
		select {
		case <-s.done:
			return s.exitedBeforeReady()
		case <-ctx.Done():
			return fmt.Errorf("server did not become ready within %s: %w", timeout, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (s *Server) exitedBeforeReady() error {
	if s.waitErr != nil {
		return fmt.Errorf("server process exited before becoming ready: %w", s.waitErr)
	}
	return errors.New("server process exited before becoming ready")
}

// IsHealthy verifies the response token emitted only by this server process.
func (s *Server) IsHealthy(ctx context.Context) bool {
	url := fmt.Sprintf("http://127.0.0.1:%d/.well-known/coraza-ftw-health/%s", s.port, s.readinessToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := (&http.Client{CheckRedirect: stopRedirects}).Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(len(s.readinessToken)+1)))
	return err == nil && resp.StatusCode == http.StatusOK && string(body) == s.readinessToken
}

func stopRedirects(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

// createFTWConfig creates the FTW configuration in memory (no file I/O)
func createFTWConfig() string {
	return fmt.Sprintf(`# Auto-generated FTW configuration for coraza-rs
logfile: %s
logmarkerheadername: X-CRS-Test
testoverride:
  input:
    dest_addr: "127.0.0.1"
    port: %d
mode: "default"
`, serverLogfile, serverPort)
}

// inventory is the complete set of FTW files below the configured directory.
type inventory struct {
	Files     int
	Tests     int
	Stages    int
	TestFiles []*test.FTWTest
}

// selectFiles applies --max-tests to files and recomputes the selected counts.
func (inv inventory) selectFiles(maxFiles int) inventory {
	if maxFiles <= 0 || maxFiles >= len(inv.TestFiles) {
		return inv
	}
	selected := inv
	selected.TestFiles = inv.TestFiles[:maxFiles]
	selected.Files = len(selected.TestFiles)
	selected.Tests = 0
	selected.Stages = 0
	for _, ftwTest := range selected.TestFiles {
		selected.Tests += len(ftwTest.Tests)
		for _, testCase := range ftwTest.Tests {
			selected.Stages += len(testCase.Stages)
		}
	}
	return selected
}

func isYAMLTest(path string) bool {
	return strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")
}

// loadInventory rejects unreadable or malformed files instead of skipping them.
func loadInventory(testDir string) (inventory, error) {
	if testDir == "" {
		return inventory{}, errors.New("test directory is required")
	}
	info, err := os.Stat(testDir)
	if err != nil {
		return inventory{}, fmt.Errorf("test directory %q: %w", testDir, err)
	}
	if !info.IsDir() {
		return inventory{}, fmt.Errorf("test directory %q is not a directory", testDir)
	}

	var testFiles []*test.FTWTest
	err = filepath.Walk(testDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() || !isYAMLTest(path) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read test file %s: %w", path, err)
		}
		ftwTest, err := test.GetTestFromYaml(data, path)
		if err != nil {
			return fmt.Errorf("parse test file %s: %w", path, err)
		}
		testFiles = append(testFiles, ftwTest)
		return nil
	})
	if err != nil {
		return inventory{}, err
	}
	if len(testFiles) == 0 {
		return inventory{}, fmt.Errorf("test directory %q contains no FTW YAML tests", testDir)
	}

	inv := inventory{Files: len(testFiles), TestFiles: testFiles}
	for _, ftwTest := range testFiles {
		inv.Tests += len(ftwTest.Tests)
		for _, testCase := range ftwTest.Tests {
			inv.Stages += len(testCase.Stages)
		}
	}
	return inv, nil
}

// runConformance executes the strict run and always writes a result manifest.
func runConformance(opts options) error {
	manifest := newResultManifest(opts)
	runErr := startAndRunConformance(opts, &manifest)
	if runErr != nil {
		manifest.OK = false
		manifest.Failures = append(manifest.Failures, runErr.Error())
	}
	if err := writeManifest(opts.manifestPath, manifest); err != nil {
		if runErr != nil {
			return fmt.Errorf("%w; also failed to write manifest: %v", runErr, err)
		}
		return err
	}
	return runErr
}

func startAndRunConformance(opts options, manifest *resultManifest) error {
	server, cleanup, err := startServer(opts)
	if err != nil {
		return err
	}
	defer cleanup()

	fmt.Printf("Server ready on http://localhost:%d\n\n", server.port)
	fmt.Println("Running FTW conformance tests...")
	fmt.Println(strings.Repeat("=", 61))
	return executeConformance(opts, server, manifest)
}

// executeConformance checks the inventory and server state, runs FTW, and fills the manifest.
func executeConformance(opts options, server *Server, manifest *resultManifest) error {
	inv, err := loadInventory(opts.testDir)
	if err != nil {
		return fmt.Errorf("test inventory: %w", err)
	}
	manifest.Counts.Files.Inventory = inv.Files
	manifest.Counts.Tests.Inventory = inv.Tests
	manifest.Counts.Stages.Inventory = inv.Stages

	if err := checkCount("file", opts.expectedFiles, inv.Files); err != nil {
		return err
	}
	if err := checkCount("test case", opts.expectedTests, inv.Tests); err != nil {
		return err
	}
	if err := checkCount("stage", opts.expectedStages, inv.Stages); err != nil {
		return err
	}

	selected := inv.selectFiles(opts.maxTests)
	manifest.Counts.Files.Selected = selected.Files
	manifest.Counts.Tests.Selected = selected.Tests
	manifest.Counts.Stages.Selected = selected.Stages

	fmt.Printf("Test inventory: %d file(s), %d test case(s), %d stage(s)\n", inv.Files, inv.Tests, inv.Stages)
	fmt.Printf("Selected files: %d file(s), %d test case(s), %d stage(s) (--max-tests limits files)\n", selected.Files, selected.Tests, selected.Stages)

	serverInventory, err := readServerInventory(server.inventoryPath)
	if err != nil {
		return fmt.Errorf("server inventory: %w", err)
	}
	if serverInventory.Mode != "strict" {
		return fmt.Errorf("server inventory reports mode %q, want \"strict\"", serverInventory.Mode)
	}
	manifest.Counts.Rules.Loaded = serverInventory.RulesLoaded
	if err := checkCount("rule", opts.expectedRules, serverInventory.RulesLoaded); err != nil {
		return err
	}
	fmt.Printf("Server rules loaded: %d\n", serverInventory.RulesLoaded)

	out := output.NewOutput("normal", os.Stdout)
	res, err := runFTWTests(selected.TestFiles, out)
	if err != nil {
		return err
	}
	if err := server.CheckAlive(); err != nil {
		return err
	}

	totalFailed := res.Stats.TotalFailed()
	manifest.Results = runResults{
		Run:          res.Stats.Run,
		Passed:       len(res.Stats.Success),
		Failed:       res.Stats.Failed,
		Skipped:      res.Stats.Skipped,
		Ignored:      res.Stats.Ignored,
		ForcedFailed: res.Stats.ForcedFail,
	}

	// Report results
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Test results:")
	fmt.Printf("   Run:     %d\n", res.Stats.Run)
	fmt.Printf("   Passed:  %d\n", len(res.Stats.Success))
	fmt.Printf("   Failed:  %d\n", totalFailed)
	fmt.Printf("   Skipped: %d\n", len(res.Stats.Skipped))
	fmt.Printf("   Ignored: %d\n", len(res.Stats.Ignored))
	fmt.Println(strings.Repeat("=", 60))

	if opts.failedOut != "" {
		failed := strings.Join(append(res.Stats.Failed, res.Stats.ForcedFail...), "\n")
		if totalFailed > 0 {
			failed += "\n"
		}
		if err := os.WriteFile(opts.failedOut, []byte(failed), 0o644); err != nil {
			return fmt.Errorf("failed to write %s: %w", opts.failedOut, err)
		}
	}

	if err := checkRunComplete(selected.Tests, res.Stats.Run); err != nil {
		return err
	}
	if totalFailed > 0 {
		return fmt.Errorf("%d test(s) failed", totalFailed)
	}

	manifest.OK = true
	return nil
}

// runFTWTests executes the selected files using go-ftw.
func runFTWTests(tests []*test.FTWTest, out *output.Output) (*runner.TestRunContext, error) {
	// Set up logging
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	// Create configuration in memory (no file I/O)
	cfg, err := config.NewConfigFromString(createFTWConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Run tests with increased timeouts for sync server
	runnerConfig := config.NewRunnerConfiguration(cfg)
	runnerConfig.ShowTime = true
	runnerConfig.ConnectTimeout = 30 * time.Second // Increase connection timeout
	runnerConfig.ReadTimeout = 30 * time.Second    // Increase read timeout for slow requests
	runnerConfig.RateLimit = 1 * time.Millisecond  // Pace requests while keeping the run sequential

	fmt.Println("Test configuration:")
	fmt.Printf("   Connect Timeout: %v\n", runnerConfig.ConnectTimeout)
	fmt.Printf("   Read Timeout: %v\n", runnerConfig.ReadTimeout)
	fmt.Printf("   Rate Limit: %v (sequential execution)\n\n", runnerConfig.RateLimit)

	res, err := runner.Run(runnerConfig, tests, out)
	if err != nil {
		return nil, fmt.Errorf("test execution failed: %w", err)
	}
	return res, nil
}

// checkCount compares an optional expected count with the observed value.
func checkCount(name string, want, got int) error {
	if want < 0 {
		return nil
	}
	if want != got {
		return fmt.Errorf("expected %d %s(s), found %d", want, name, got)
	}
	return nil
}

// checkRunComplete rejects runs that report fewer tests than the inventory selected.
func checkRunComplete(expected, run int) error {
	if run != expected {
		return fmt.Errorf("incomplete test output: expected %d test case(s), go-ftw reported %d run", expected, run)
	}
	return nil
}

// resultManifest is the machine-readable conformance result.
type resultManifest struct {
	Mode     string           `json:"mode"`
	OK       bool             `json:"ok"`
	Strict   bool             `json:"strict"`
	TestDir  string           `json:"test_dir"`
	Expected expectedManifest `json:"expected"`
	Counts   countsManifest   `json:"counts"`
	Results  runResults       `json:"results"`
	Failures []string         `json:"failures"`
}

type expectedManifest struct {
	Rules  *int `json:"rules"`
	Files  *int `json:"files"`
	Tests  *int `json:"tests"`
	Stages *int `json:"stages"`
}

type countsManifest struct {
	Files  countValue `json:"files"`
	Tests  countValue `json:"tests"`
	Stages countValue `json:"stages"`
	Rules  ruleCount  `json:"rules"`
}

type countValue struct {
	Inventory int `json:"inventory"`
	Selected  int `json:"selected"`
}

type ruleCount struct {
	Loaded int `json:"loaded"`
}

type runResults struct {
	Run          int      `json:"run"`
	Passed       int      `json:"passed"`
	Failed       []string `json:"failed"`
	Skipped      []string `json:"skipped"`
	Ignored      []string `json:"ignored"`
	ForcedFailed []string `json:"forced_failed"`
}

func newResultManifest(opts options) resultManifest {
	return resultManifest{
		Mode:    string(opts.mode),
		Strict:  true,
		TestDir: opts.testDir,
		Expected: expectedManifest{
			Rules:  optionalCount(opts.expectedRules),
			Files:  optionalCount(opts.expectedFiles),
			Tests:  optionalCount(opts.expectedTests),
			Stages: optionalCount(opts.expectedStages),
		},
		Results: runResults{
			Failed:       []string{},
			Skipped:      []string{},
			Ignored:      []string{},
			ForcedFailed: []string{},
		},
		Failures: []string{},
	}
}

func optionalCount(value int) *int {
	if value < 0 {
		return nil
	}
	return &value
}

func writeManifest(path string, manifest resultManifest) error {
	if path == "" {
		return errors.New("manifest path is empty")
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write manifest %s: %w", path, err)
	}
	return nil
}

// serverInventory is the startup inventory written by the Rust server in strict mode.
type serverInventory struct {
	Mode              string   `json:"mode"`
	RulesLoaded       int      `json:"rules_loaded"`
	SkippedDirectives []string `json:"skipped_directives"`
	ExpectedRules     *int     `json:"expected_rules"`
}

func readServerInventory(path string) (serverInventory, error) {
	if path == "" {
		return serverInventory{}, errors.New("inventory path is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return serverInventory{}, fmt.Errorf("read %s: %w", path, err)
	}
	var inventory serverInventory
	if err := json.Unmarshal(data, &inventory); err != nil {
		return serverInventory{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return inventory, nil
}

// testServerHealth performs basic server health check
func testServerHealth() error {
	fmt.Println("\nRunning basic health checks...")
	return testServerHealthAt(
		fmt.Sprintf("http://127.0.0.1:%d", serverPort),
		&http.Client{Timeout: 5 * time.Second},
	)
}

func testServerHealthAt(baseURL string, client *http.Client) error {
	clientWithoutRedirects := *client
	clientWithoutRedirects.CheckRedirect = stopRedirects
	tests := []struct {
		method string
		path   string
	}{
		{"GET", "/"},
		{"POST", "/test"},
		{"GET", "/search?q=test"},
	}

	for _, test := range tests {
		fmt.Printf("   Testing: %s %s... ", test.method, test.path)

		req, err := http.NewRequest(test.method, baseURL+test.path, nil)
		if err != nil {
			fmt.Println("FAIL")
			return fmt.Errorf("request setup failed: %w", err)
		}
		resp, err := clientWithoutRedirects.Do(req)
		if err != nil {
			fmt.Println("FAIL")
			return fmt.Errorf("request failed: %w", err)
		}
		status := resp.StatusCode
		_ = resp.Body.Close()
		if status == http.StatusOK {
			fmt.Println("PASS")
		} else {
			fmt.Printf("FAIL (HTTP %d)\n", status)
			return fmt.Errorf("health check %s %s returned HTTP status %d", test.method, test.path, status)
		}
	}

	fmt.Println("\nHealth checks passed")
	return nil
}
