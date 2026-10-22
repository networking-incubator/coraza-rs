// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// runCommand executes one shell command with captured stdout and stderr. It
// returns the exit status and only fails when the command could not be started
// or its output files could not be written.
func runCommand(
	ctx context.Context,
	command string,
	dir string,
	env map[string]string,
	stdoutPath string,
	stderrPath string,
) (int, error) {
	if err := validateCommand(command); err != nil {
		return -1, err
	}
	if err := os.MkdirAll(filepath.Dir(stdoutPath), 0o755); err != nil {
		return -1, err
	}
	if err := os.MkdirAll(filepath.Dir(stderrPath), 0o755); err != nil {
		return -1, err
	}
	stdout, err := os.Create(stdoutPath)
	if err != nil {
		return -1, err
	}
	stderr, err := os.Create(stderrPath)
	if err != nil {
		_ = stdout.Close()
		return -1, err
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Dir = dir
	cmd.Env = mergeEnv(os.Environ(), env)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	runErr := cmd.Run()
	closeErr := errors.Join(stdout.Close(), stderr.Close())
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		return -1, errors.Join(runErr, closeErr)
	}
	if closeErr != nil {
		return -1, closeErr
	}
	return 0, nil
}

// mergeEnv returns env with the provided keys replaced, never duplicated.
func mergeEnv(env []string, overrides map[string]string) []string {
	merged := make([]string, 0, len(env)+len(overrides))
	for _, entry := range env {
		key, _, found := strings.Cut(entry, "=")
		if found {
			if _, replaced := overrides[key]; replaced {
				continue
			}
		}
		merged = append(merged, entry)
	}
	for key, value := range overrides {
		merged = append(merged, key+"="+value)
	}
	return merged
}

// createRunDir creates a new exclusive run directory under outputRoot. Every
// run keeps its own artifacts so repeated runs never overwrite evidence.
func createRunDir(outputRoot, kind string) (string, error) {
	if err := os.MkdirAll(outputRoot, 0o755); err != nil {
		return "", err
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	for attempt := 0; attempt < 1000; attempt++ {
		name := kind + "-" + stamp
		if attempt > 0 {
			name = fmt.Sprintf("%s-%d", name, attempt+1)
		}
		runDir := filepath.Join(outputRoot, name)
		err := os.Mkdir(runDir, 0o755)
		if err == nil {
			if err := os.Mkdir(filepath.Join(runDir, "raw"), 0o755); err != nil {
				return "", err
			}
			return runDir, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
	}
	return "", errors.New("cannot allocate a unique run directory")
}
