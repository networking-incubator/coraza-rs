// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

// Command coraza-coordinator validates benchmark identities, runs the
// correctness parity gate and orchestrates the paired Go-versus-Rust timing
// protocol described in benchmarks/coraza/README.md.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

const (
	// defaultCheckResolveCommand reports the Go engine identity as JSON from
	// the isolated Go benchmark module.
	defaultCheckResolveCommand = "go run ./cmd/checkresolve"
	// defaultParityCommand is the correctness parity runner added by the
	// parity work package. The coordinator appends --workloads.
	defaultParityCommand = "go run ./cmd/parity"
	// defaultRustBuildCommand builds the Rust driver once and emits cargo
	// artifact messages so the coordinator can find the executable.
	defaultRustBuildCommand = "cargo build --locked --release -p coraza --bench coraza_workload --message-format=json"
	// defaultGoDriverPackage is the Go timing driver package. The timing mode
	// lands with the Go workload consumer.
	defaultGoDriverPackage = "./cmd/bench"
	// defaultGoDriverBinary is the file name built under the run directory.
	defaultGoDriverBinary = "coraza-go-driver"
	// minRepetitions is the protocol minimum for paired repetitions.
	minRepetitions = 3
	// maxIterations bounds one driver invocation to catch typos and hostile
	// configuration while leaving room for production measurements.
	maxIterations = 10_000_000
)

// config holds the resolved command-line and environment configuration.
type config struct {
	repoRoot        string
	workloads       string
	outputRoot      string
	goModule        string
	checkresolveCmd string
	parityCmd       string
	parityReport    string
	goProfile       string
	repetitions     int
	iterations      int
	rustBuildCmd    string
	rustDriverCmd   string
	goBuildCmd      string
	goDriverCmd     string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "coraza coordinator: %v\n", err)
		os.Exit(1)
	}
}

// run dispatches one coordinator subcommand.
func run(args []string) error {
	if len(args) == 0 {
		printUsage(os.Stderr)
		return errors.New("missing subcommand")
	}
	switch args[0] {
	case "parity":
		return runParityCommand(args[1:])
	case "bench":
		return runBenchCommand(args[1:])
	case "help", "-h", "--help":
		printUsage(os.Stdout)
		return nil
	default:
		printUsage(os.Stderr)
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

// printUsage prints the command surface. Flag details come from each
// subcommand's -h output.
func printUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: coraza-coordinator <command> [flags]

Commands:
  parity   validate the workload and engine identity, then run the
           correctness parity gate. No timing runs.
  bench    run the correctness parity gate, build both drivers once, and
           run at least three paired timing repetitions in alternating order.
  help     print this text

Environment variables (flags take precedence):
  CORAZA_REPO               repository root (default: git top level)
  CORAZA_WORKLOADS          workload directory (default: benchmarks/coraza/workloads)
  BENCH_OUT                 artifact root (default: target/coraza-bench)
  CORAZA_GO_MODULE          isolated Go module (default: benchmarks/coraza/go)
  CORAZA_CHECKRESOLVE_CMD   checkresolve command (default: go run ./cmd/checkresolve)
  CORAZA_GO_PROFILE         expected Go profile: auto, upstream or local (default: auto)
  CORAZA_PARITY_CMD         parity command (default: go run ./cmd/parity)
  CORAZA_PARITY_REPORT      optional per-case parity report JSON
  CORAZA_REPETITIONS        paired repetitions, at least 3 (default: 3)
  CORAZA_ITERATIONS         driver --iterations value (default: 1000)
  CORAZA_RUST_BUILD_CMD     Rust build command override
  CORAZA_RUST_DRIVER_CMD    Rust driver command override
  CORAZA_GO_BUILD_CMD       Go build command override
  CORAZA_GO_DRIVER_CMD      Go driver command override

Run "coraza-coordinator <command> -h" for flag details.
`)
}

// parseConfig parses one subcommand's flags, applies environment defaults and
// validates the resolved configuration.
func parseConfig(name string, args []string) (*config, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cfg := &config{}
	var repetitions, iterations string
	fs.StringVar(&cfg.repoRoot, "repo", envOr("CORAZA_REPO", ""), "repository root (default: git top level)")
	fs.StringVar(&cfg.workloads, "workloads", envOr("CORAZA_WORKLOADS", ""), "workload directory")
	fs.StringVar(&cfg.outputRoot, "output", envOr("BENCH_OUT", ""), "artifact root directory")
	fs.StringVar(&cfg.goModule, "go-module", envOr("CORAZA_GO_MODULE", ""), "isolated Go benchmark module")
	fs.StringVar(&cfg.checkresolveCmd, "checkresolve-command", envOr("CORAZA_CHECKRESOLVE_CMD", defaultCheckResolveCommand), "Go engine resolution command")
	fs.StringVar(&cfg.goProfile, "go-profile", envOr("CORAZA_GO_PROFILE", "auto"), "expected Go profile: auto, upstream or local")
	fs.StringVar(&cfg.parityCmd, "parity-command", envOr("CORAZA_PARITY_CMD", defaultParityCommand), "correctness parity command")
	fs.StringVar(&cfg.parityReport, "parity-report", envOr("CORAZA_PARITY_REPORT", ""), "optional per-case parity report JSON")
	fs.StringVar(&repetitions, "repetitions", envOr("CORAZA_REPETITIONS", strconv.Itoa(minRepetitions)), "paired repetitions, at least 3")
	fs.StringVar(&iterations, "iterations", envOr("CORAZA_ITERATIONS", "1000"), "driver --iterations value")
	fs.StringVar(&cfg.rustBuildCmd, "rust-build-command", envOr("CORAZA_RUST_BUILD_CMD", ""), "Rust build command override")
	fs.StringVar(&cfg.rustDriverCmd, "rust-driver-command", envOr("CORAZA_RUST_DRIVER_CMD", ""), "Rust driver command override")
	fs.StringVar(&cfg.goBuildCmd, "go-build-command", envOr("CORAZA_GO_BUILD_CMD", ""), "Go build command override")
	fs.StringVar(&cfg.goDriverCmd, "go-driver-command", envOr("CORAZA_GO_DRIVER_CMD", ""), "Go driver command override")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, nil
		}
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	var err error
	if cfg.repetitions, err = strconv.Atoi(repetitions); err != nil {
		return nil, fmt.Errorf("repetitions must be an integer: %w", err)
	}
	if cfg.iterations, err = strconv.Atoi(iterations); err != nil {
		return nil, fmt.Errorf("iterations must be an integer: %w", err)
	}
	if err := cfg.resolve(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// resolve fills derived defaults and validates values that must hold for every
// subcommand.
func (c *config) resolve() error {
	if c.repoRoot == "" {
		c.repoRoot = defaultRepoRoot()
	}
	var err error
	if c.repoRoot, err = absolute(c.repoRoot); err != nil {
		return fmt.Errorf("repository root: %w", err)
	}
	if c.workloads, err = c.absoluteOr(c.workloads, "benchmarks", "coraza", "workloads"); err != nil {
		return fmt.Errorf("workload directory: %w", err)
	}
	if c.outputRoot, err = c.absoluteOr(c.outputRoot, "target", "coraza-bench"); err != nil {
		return fmt.Errorf("output directory: %w", err)
	}
	if c.goModule, err = c.absoluteOr(c.goModule, "benchmarks", "coraza", "go"); err != nil {
		return fmt.Errorf("Go module: %w", err)
	}
	if c.checkresolveCmd == "" {
		c.checkresolveCmd = defaultCheckResolveCommand
	}
	if c.parityCmd == "" {
		c.parityCmd = defaultParityCommand
	}
	switch c.goProfile {
	case "", "auto":
		c.goProfile = "auto"
	case "upstream", "local":
	default:
		return fmt.Errorf("go-profile must be auto, upstream or local, got %q", c.goProfile)
	}
	if c.repetitions < minRepetitions {
		return fmt.Errorf("repetitions must be at least %d, got %d", minRepetitions, c.repetitions)
	}
	if c.iterations <= 0 || c.iterations > maxIterations {
		return fmt.Errorf("iterations must be between 1 and %d, got %d", maxIterations, c.iterations)
	}
	if c.rustBuildCmd != "" && c.rustDriverCmd == "" {
		return errors.New("a Rust build command requires a Rust driver command so the built executable is known")
	}
	if c.goBuildCmd != "" && c.goDriverCmd == "" {
		return errors.New("a Go build command requires a Go driver command so the built executable is known")
	}
	return nil
}

// absoluteOr returns the absolute form of value, or of the repository-relative
// default parts when value is empty.
func (c *config) absoluteOr(value string, parts ...string) (string, error) {
	if value == "" {
		value = filepath.Join(append([]string{c.repoRoot}, parts...)...)
	}
	return absolute(value)
}

// absolute returns a clean absolute path.
func absolute(path string) (string, error) {
	if path == "" {
		return "", errors.New("path is empty")
	}
	value, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(value), nil
}

// envOr returns the environment value when set and non-empty, otherwise the
// fallback.
func envOr(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}
