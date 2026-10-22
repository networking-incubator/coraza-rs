// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"path/filepath"
	"time"
)

// parityInvocation is the exact correctness gate command, including the
// workload argument the runner consumes.
func parityInvocation(cfg *config) string {
	return cfg.parityCmd + " --workloads " + shellQuote(cfg.workloads)
}

// runParityGate executes the correctness runner. A non-zero exit status stops
// the caller before any timing work; outcome comparison belongs to the runner.
func runParityGate(ctx context.Context, cfg *config, runDir string) (parityRecord, error) {
	stdoutPath := filepath.Join(runDir, "raw", "parity.stdout.log")
	stderrPath := filepath.Join(runDir, "raw", "parity.stderr.log")
	record := parityRecord{
		Attempted: true,
		Command:   parityInvocation(cfg),
		Dir:       cfg.goModule,
		Stdout:    relativeArtifact(runDir, stdoutPath),
		Stderr:    relativeArtifact(runDir, stderrPath),
	}
	if cfg.parityReport != "" {
		record.ReportPath = cfg.parityReport
	}
	exitCode, err := runCommand(ctx, record.Command, record.Dir, goEnv(), stdoutPath, stderrPath)
	if err != nil {
		return record, fmt.Errorf("run parity command: %w", err)
	}
	record.ExitCode = exitCode
	if exitCode != 0 {
		return record, fmt.Errorf(
			"correctness parity gate failed with exit status %d; see %s",
			exitCode, record.Stderr,
		)
	}
	record.Passed = true
	return record, nil
}

// runParityCommand implements the parity subcommand. It validates identities,
// writes them, runs the gate and stops. Timing never starts.
func runParityCommand(args []string) (retErr error) {
	cfg, err := parseConfig("parity", args)
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
	runDir, err := createRunDir(cfg.outputRoot, "parity")
	if err != nil {
		return fmt.Errorf("create artifact directory: %w", err)
	}
	started := time.Now().UTC()
	document := parityDocument{
		SchemaVersion: resultSchemaVersion,
		Kind:          "parity",
		RunID:         filepath.Base(runDir),
		StartedAt:     started.Format(time.RFC3339),
		Status:        "failed",
		Workload:      workloadIdentityFrom(workload),
	}
	resultPath := filepath.Join(runDir, "parity.json")
	defer func() {
		document.FinishedAt = time.Now().UTC().Format(time.RFC3339)
		if retErr != nil {
			document.Error = retErr.Error()
		} else {
			document.Status = "passed"
		}
		if err := writeJSON(resultPath, document); err != nil && retErr == nil {
			retErr = fmt.Errorf("write parity result: %w", err)
		}
		fmt.Printf("parity artifacts: %s\n", runDir)
	}()

	commands := commandsRecord{
		CheckResolve: commandRecord{Command: cfg.checkresolveCmd, Dir: cfg.goModule},
		Parity:       commandRecord{Command: parityInvocation(cfg), Dir: cfg.goModule},
	}
	ctx := context.Background()
	recordedIdentity, err := gatherIdentity(ctx, cfg, runDir, workload, commands)
	if err != nil {
		return err
	}
	document.Identity = recordedIdentity
	if err := writeJSON(filepath.Join(runDir, "identity.json"), recordedIdentity); err != nil {
		return fmt.Errorf("write identity: %w", err)
	}
	parity, err := runParityGate(ctx, cfg, runDir)
	document.Parity = parity
	if err != nil {
		return err
	}
	return nil
}
