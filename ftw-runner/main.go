// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

// Package main provides a test harness for running go-ftw tests against coraza-rs
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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

var serverLogfile string

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	// Parse command-line flags
	rulesFile := flag.String("rules", "", "Path to CRS rules file (e.g., crs-test.conf)")
	maxTests := flag.Int("max-tests", 0, "Maximum number of tests to run (0 = all tests)")
	testDir := flag.String("test-dir", "", "Path to test directory (default: ../../coraza-coreruleset/tests)")
	failedOut := flag.String("failed-out", "", "File to write the IDs of the failed tests to, one per line")
	flag.Parse()

	fmt.Println("Coraza-RS FTW test runner")

	// Verify server binary exists
	if _, err := os.Stat(serverBinaryPath); err != nil {
		return fmt.Errorf("server binary not found at %s; build it with cargo build --release -p coraza --example ftw_server_async --features async-server: %w", serverBinaryPath, err)
	}
	fmt.Printf("Found server binary: %s\n", serverBinaryPath)

	auditDir, err := os.MkdirTemp("", "coraza-ftw-audit-")
	if err != nil {
		return fmt.Errorf("failed to create audit directory: %w", err)
	}
	serverLogfile = filepath.Join(auditDir, "audit.log")
	defer func() {
		if err := os.RemoveAll(auditDir); err != nil {
			fmt.Fprintf(os.Stderr, "failed to remove audit directory %s: %v\n", auditDir, err)
		}
	}()

	// Start server
	fmt.Println("Starting FTW server...")
	server := &Server{
		port:      serverPort,
		logfile:   serverLogfile,
		rulesFile: *rulesFile,
	}

	if err := server.Start(); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	defer server.Stop()

	// Wait for server to be ready
	fmt.Println("Waiting for server to be ready...")
	if err := server.WaitUntilReady(30 * time.Second); err != nil {
		return err
	}
	fmt.Printf("Server ready on http://localhost:%d\n\n", serverPort)

	// Run FTW tests
	fmt.Println("Running FTW tests...")
	fmt.Println(strings.Repeat("=", 61))
	if err := runFTW(*maxTests, *testDir, *failedOut); err != nil {
		return fmt.Errorf("FTW run failed: %w", err)
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("All tests complete!")
	return nil
}

// Server represents the Rust FTW server process
type Server struct {
	cmd            *exec.Cmd
	port           int
	logfile        string
	rulesFile      string
	readinessToken string
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

// runFTW executes go-ftw tests using the library directly
func runFTW(maxTests int, customTestDir string, failedOut string) error {
	// Set up logging
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	// Create configuration in memory (no file I/O)
	configYaml := createFTWConfig()
	cfg, err := config.NewConfigFromString(configYaml)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Determine test directory
	testDir := customTestDir
	if testDir == "" {
		testDir = filepath.Join("..", "..", "coraza-coreruleset", "tests")
	}

	if _, err := os.Stat(testDir); os.IsNotExist(err) {
		fmt.Printf("Test directory not found: %s\n", testDir)
		fmt.Println("   Running server health checks only")
		return testServerHealth()
	}

	// Get test files recursively from all subdirectories
	var tests []*test.FTWTest
	err = filepath.Walk(testDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-YAML files
		if info.IsDir() || (!strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml")) {
			return nil
		}

		// Skip non-test files (tests.go, etc.)
		if strings.HasSuffix(path, ".go") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("Skipping %s: %v\n", path, err)
			return nil
		}

		ftwTest, err := test.GetTestFromYaml(data, path)
		if err != nil {
			fmt.Printf("Skipping %s: %v\n", path, err)
			return nil
		}

		tests = append(tests, ftwTest)
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk test directory: %w", err)
	}

	if len(tests) == 0 {
		return fmt.Errorf("test directory %q contains no valid FTW tests", testDir)
	}

	// Limit number of tests if requested
	totalTests := len(tests)
	if maxTests > 0 && maxTests < len(tests) {
		tests = tests[:maxTests]
		fmt.Printf("Loaded %d test file(s) from CRS test suite (limited to first %d)\n\n", totalTests, maxTests)
	} else {
		fmt.Printf("Loaded %d test file(s) from CRS test suite\n\n", len(tests))
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

	out := output.NewOutput("normal", os.Stdout)
	res, err := runner.Run(runnerConfig, tests, out)
	if err != nil {
		return fmt.Errorf("test execution failed: %w", err)
	}

	// Report results
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Printf("Test results:\n")
	fmt.Printf("   Run:     %d\n", res.Stats.Run)
	fmt.Printf("   Passed:  %d\n", res.Stats.Run-len(res.Stats.Failed))
	fmt.Printf("   Failed:  %d\n", len(res.Stats.Failed))
	fmt.Printf("   Ignored: %d\n", len(res.Stats.Ignored))
	fmt.Println(strings.Repeat("=", 60))

	if failedOut != "" {
		failed := strings.Join(res.Stats.Failed, "\n") + "\n"
		if err := os.WriteFile(failedOut, []byte(failed), 0o644); err != nil {
			return fmt.Errorf("failed to write %s: %w", failedOut, err)
		}
	}

	if len(res.Stats.Failed) > 0 {
		return fmt.Errorf("%d test(s) failed", len(res.Stats.Failed))
	}

	return nil
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
