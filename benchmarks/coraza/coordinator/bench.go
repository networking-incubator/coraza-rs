// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"
)

// cargoArtifact is the subset of a cargo JSON message used to find the built
// bench executable.
type cargoArtifact struct {
	Reason     string `json:"reason"`
	Executable string `json:"executable"`
	Target     struct {
		Name string   `json:"name"`
		Kind []string `json:"kind"`
	} `json:"target"`
}

// runBenchCommand implements the bench subcommand: identity validation,
// correctness gate, one build per driver and the paired timing protocol.
func runBenchCommand(args []string) (retErr error) {
	cfg, err := parseConfig("bench", args)
	if err != nil {
		return err
	}
	if cfg == nil {
		return nil
	}
	workload, err := loadWorkload(cfg.workloads)
	if err != nil {
		return err
	}
	runDir, err := createRunDir(cfg.outputRoot, "bench")
	if err != nil {
		return fmt.Errorf("create artifact directory: %w", err)
	}
	result := benchResult{
		SchemaVersion: resultSchemaVersion,
		Kind:          "bench",
		RunID:         filepath.Base(runDir),
		StartedAt:     time.Now().UTC().Format(time.RFC3339),
		Status:        "failed",
		Workload:      workloadIdentityFrom(workload),
		Protocol: protocolRecord{
			TimingContract: timingContractVersion,
			Repetitions:    cfg.repetitions,
			Iterations:     cfg.iterations,
		},
		Runs:  []runRecord{},
		Cases: []caseResult{},
	}
	resultPath := filepath.Join(runDir, "run.json")
	defer func() {
		result.FinishedAt = time.Now().UTC().Format(time.RFC3339)
		if retErr != nil {
			result.Status = "failed"
			result.Error = retErr.Error()
		} else {
			result.Status = "passed"
		}
		if err := writeJSON(resultPath, result); err != nil && retErr == nil {
			retErr = fmt.Errorf("write bench result: %w", err)
		}
		fmt.Printf("bench artifacts: %s\n", runDir)
	}()

	ctx := context.Background()
	commands := plannedCommands(cfg, runDir)
	recordedIdentity, err := gatherIdentity(ctx, cfg, runDir, workload, commands)
	if err != nil {
		return err
	}
	result.Identity = recordedIdentity
	if err := writeIdentity(runDir, recordedIdentity); err != nil {
		return err
	}

	parity, err := runParityGate(ctx, cfg, runDir)
	result.Parity = parity
	if err != nil {
		return err
	}
	report, err := loadParityReport(cfg.parityReport, workload)
	if err != nil {
		return err
	}

	rustCommand, rustBuild, err := buildRustDriver(ctx, cfg, runDir)
	if err != nil {
		return err
	}
	result.Identity.Commands.RustBuild = rustBuild
	result.Identity.Commands.RustDriver = &commandRecord{Command: rustCommand, Dir: cfg.repoRoot}
	goCommand, goBuild, err := buildGoDriver(ctx, cfg, runDir)
	if err != nil {
		return err
	}
	result.Identity.Commands.GoBuild = goBuild
	result.Identity.Commands.GoDriver = &commandRecord{Command: goCommand, Dir: cfg.goModule}
	if err := writeIdentity(runDir, result.Identity); err != nil {
		return err
	}

	for repetition := 0; repetition < cfg.repetitions; repetition++ {
		for position, engine := range runOrder(repetition) {
			command := rustCommand
			dir := cfg.repoRoot
			if engine == "go" {
				command = goCommand
				dir = cfg.goModule
			}
			run, err := executeTimingRun(ctx, cfg, workload, runDir, repetition+1, position+1, engine, command, dir)
			result.Runs = append(result.Runs, run)
			if err != nil {
				return err
			}
		}
	}
	result.Cases = summarizeCases(workload, result.Runs, report)
	return nil
}

// plannedCommands records the commands known before builds resolve executable
// paths. Driver entries stay absent until the build produces them.
func plannedCommands(cfg *config, runDir string) commandsRecord {
	commands := commandsRecord{
		CheckResolve: commandRecord{Command: cfg.checkresolveCmd, Dir: cfg.goModule},
		Parity:       commandRecord{Command: parityInvocation(cfg), Dir: cfg.goModule},
	}
	if cfg.rustDriverCmd != "" {
		commands.RustDriver = &commandRecord{Command: cfg.rustDriverCmd, Dir: cfg.repoRoot}
		if cfg.rustBuildCmd != "" {
			commands.RustBuild = &commandRecord{Command: cfg.rustBuildCmd, Dir: cfg.repoRoot}
		}
	} else {
		commands.RustBuild = &commandRecord{Command: defaultRustBuildCommand, Dir: cfg.repoRoot}
	}
	if cfg.goDriverCmd != "" {
		commands.GoDriver = &commandRecord{Command: cfg.goDriverCmd, Dir: cfg.goModule}
		if cfg.goBuildCmd != "" {
			commands.GoBuild = &commandRecord{Command: cfg.goBuildCmd, Dir: cfg.goModule}
		}
	} else {
		binary := filepath.Join(runDir, "bin", defaultGoDriverBinary)
		commands.GoBuild = &commandRecord{
			Command: "go build -o " + shellQuote(binary) + " " + defaultGoDriverPackage,
			Dir:     cfg.goModule,
		}
	}
	return commands
}

// writeIdentity writes the identity document used by both subcommands.
func writeIdentity(runDir string, value identity) error {
	if err := writeJSON(filepath.Join(runDir, "identity.json"), value); err != nil {
		return fmt.Errorf("write identity: %w", err)
	}
	return nil
}

// buildRustDriver builds the Rust driver once and returns the exact command
// that runs the resolved executable.
func buildRustDriver(ctx context.Context, cfg *config, runDir string) (string, *commandRecord, error) {
	if cfg.rustDriverCmd != "" {
		var build *commandRecord
		if cfg.rustBuildCmd != "" {
			build = &commandRecord{Command: cfg.rustBuildCmd, Dir: cfg.repoRoot}
			if err := runBuild(ctx, *build, runDir, "rust"); err != nil {
				return "", build, err
			}
		}
		return cfg.rustDriverCmd, build, nil
	}
	build := &commandRecord{Command: defaultRustBuildCommand, Dir: cfg.repoRoot}
	if err := runBuild(ctx, *build, runDir, "rust"); err != nil {
		return "", build, err
	}
	executable, err := cargoExecutable(filepath.Join(runDir, "raw", "build-rust.stdout.log"))
	if err != nil {
		return "", build, err
	}
	return shellQuote(executable), build, nil
}

// buildGoDriver builds the Go driver once and returns the exact command that
// runs the resolved executable.
func buildGoDriver(ctx context.Context, cfg *config, runDir string) (string, *commandRecord, error) {
	if cfg.goDriverCmd != "" {
		var build *commandRecord
		if cfg.goBuildCmd != "" {
			build = &commandRecord{Command: cfg.goBuildCmd, Dir: cfg.goModule}
			if err := runBuild(ctx, *build, runDir, "go"); err != nil {
				return "", build, err
			}
		}
		return cfg.goDriverCmd, build, nil
	}
	binary := filepath.Join(runDir, "bin", defaultGoDriverBinary)
	if err := os.MkdirAll(filepath.Dir(binary), 0o755); err != nil {
		return "", nil, err
	}
	build := &commandRecord{
		Command: "go build -o " + shellQuote(binary) + " " + defaultGoDriverPackage,
		Dir:     cfg.goModule,
	}
	if err := runBuild(ctx, *build, runDir, "go"); err != nil {
		return "", build, err
	}
	info, err := os.Stat(binary)
	if err != nil {
		return "", build, fmt.Errorf("Go driver build did not produce %s: %w", binary, err)
	}
	if info.IsDir() {
		return "", build, fmt.Errorf("Go driver build produced a directory at %s", binary)
	}
	return shellQuote(binary), build, nil
}

// runBuild executes one build command and captures its output.
func runBuild(ctx context.Context, build commandRecord, runDir, label string) error {
	stdoutPath := filepath.Join(runDir, "raw", "build-"+label+".stdout.log")
	stderrPath := filepath.Join(runDir, "raw", "build-"+label+".stderr.log")
	exitCode, err := runCommand(ctx, build.Command, build.Dir, goEnvIfGo(label), stdoutPath, stderrPath)
	if err != nil {
		return fmt.Errorf("%s driver build: %w", label, err)
	}
	if exitCode != 0 {
		return fmt.Errorf(
			"%s driver build exited with status %d; see %s",
			label, exitCode, relativeArtifact(runDir, stderrPath),
		)
	}
	return nil
}

// goEnvIfGo applies the isolated Go environment only to Go commands. Cargo
// inherits the caller environment unchanged.
func goEnvIfGo(label string) map[string]string {
	if label == "go" {
		return goEnv()
	}
	return nil
}

// cargoExecutable finds the bench executable in cargo JSON messages.
func cargoExecutable(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("read cargo build output: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	found := ""
	for {
		var message cargoArtifact
		err := decoder.Decode(&message)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("parse cargo build output: %w", err)
		}
		if message.Reason != "compiler-artifact" || message.Executable == "" {
			continue
		}
		if message.Target.Name == "coraza_workload" && slices.Contains(message.Target.Kind, "bench") {
			found = message.Executable
		}
	}
	if found == "" {
		return "", errors.New("cargo build output did not name the coraza_workload bench executable")
	}
	return found, nil
}

// executeTimingRun runs one driver invocation and validates its raw output
// before returning it.
func executeTimingRun(
	ctx context.Context,
	cfg *config,
	workload *workload,
	runDir string,
	round int,
	position int,
	engine string,
	command string,
	dir string,
) (runRecord, error) {
	label := fmt.Sprintf("round-%02d-%s", round, engine)
	timingPath := filepath.Join(runDir, "raw", label+".timing.json")
	stdoutPath := filepath.Join(runDir, "raw", label+".stdout.log")
	stderrPath := filepath.Join(runDir, "raw", label+".stderr.log")
	invocation := command +
		" --workloads " + shellQuote(workload.Root) +
		" --timing " + shellQuote(timingPath) +
		" --iterations " + strconv.Itoa(cfg.iterations)
	record := runRecord{
		Round:     round,
		Position:  position,
		Engine:    engine,
		Command:   invocation,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		RawTiming: relativeArtifact(runDir, timingPath),
		Stdout:    relativeArtifact(runDir, stdoutPath),
		Stderr:    relativeArtifact(runDir, stderrPath),
	}
	exitCode, err := runCommand(ctx, invocation, dir, nil, stdoutPath, stderrPath)
	record.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	record.ExitCode = exitCode
	if err != nil {
		return record, fmt.Errorf("%s driver: %w", engine, err)
	}
	if exitCode != 0 {
		return record, fmt.Errorf(
			"%s driver exited with status %d; see %s",
			engine, exitCode, record.Stderr,
		)
	}
	cases, err := readTiming(timingPath, engine, workload, cfg.iterations)
	if err != nil {
		return record, fmt.Errorf("%s driver: %w", engine, err)
	}
	record.Cases = cases
	return record, nil
}
