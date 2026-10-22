// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	// identitySchemaVersion versions the identity document.
	identitySchemaVersion = 1
	// engineModulePath is the Go engine module under comparison.
	engineModulePath = "github.com/corazawaf/coraza/v3"
	// maxResolutionBytes bounds checkresolve output.
	maxResolutionBytes = 1 << 20
)

// goModule is the subset of `go list -m -json` recorded in the resolution
// report.
type goModule struct {
	Path    string    `json:"Path"`
	Version string    `json:"Version"`
	Dir     string    `json:"Dir"`
	GoMod   string    `json:"GoMod"`
	Replace *goModule `json:"Replace"`
}

// goResolution mirrors the JSON printed by cmd/checkresolve.
type goResolution struct {
	Profile        string   `json:"profile"`
	GoBinary       string   `json:"go_binary"`
	GoVersion      string   `json:"go_version"`
	GOWork         string   `json:"gowork"`
	GOToolchain    string   `json:"gotoolchain"`
	Engine         goModule `json:"engine"`
	EngineDir      string   `json:"engine_dir"`
	EngineRevision string   `json:"engine_revision"`
	EngineDirty    bool     `json:"engine_dirty"`
}

// goEnv is applied to every Go command so an ambient workspace or implicit
// toolchain cannot substitute another engine.
func goEnv() map[string]string {
	return map[string]string{"GOWORK": "off", "GOTOOLCHAIN": "local"}
}

// defaultRepoRoot returns the git top-level directory for the current working
// directory, falling back to the working directory outside a repository.
func defaultRepoRoot() string {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err == nil {
		if root := strings.TrimSpace(string(out)); root != "" {
			return root
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return cwd
}

// repositoryIdentity records the exact repository revision and whether tracked
// files were modified. Untracked files are ignored so local notes do not block
// a run.
func collectRepositoryIdentity(root string) (repositoryIdentity, error) {
	revision, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil {
		return repositoryIdentity{}, err
	}
	if !isHexCommit(revision) {
		return repositoryIdentity{}, fmt.Errorf("repository revision %q is not a 40-character hex commit", revision)
	}
	status, err := gitOutput(root, "status", "--porcelain", "--untracked-files=no")
	if err != nil {
		return repositoryIdentity{}, err
	}
	return repositoryIdentity{
		Root:     root,
		Revision: revision,
		Dirty:    status != "",
	}, nil
}

// gitOutput runs one read-only git command and trims its output.
func gitOutput(root string, args ...string) (string, error) {
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	out, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// toolVersions records the tools that affect reproduction. A missing tool is
// reported in the artifact instead of failing a parity-only run.
func toolVersions() map[string]string {
	tools := map[string]string{}
	for _, tool := range []struct {
		name string
		args []string
	}{
		{name: "go", args: []string{"version"}},
		{name: "rustc", args: []string{"--version"}},
		{name: "cargo", args: []string{"--version"}},
	} {
		out, err := exec.Command(tool.name, tool.args...).CombinedOutput()
		if err != nil {
			tools[tool.name] = "unavailable: " + err.Error()
			continue
		}
		tools[tool.name] = strings.TrimSpace(string(out))
	}
	return tools
}

// checkResolution runs the configured checkresolve command and requires a zero
// exit status and a well-formed report. It refuses to run when the isolated Go
// module is missing.
func checkResolution(ctx context.Context, cfg *config, runDir string) (goResolution, error) {
	moduleFile := filepath.Join(cfg.goModule, "go.mod")
	info, err := os.Stat(moduleFile)
	if err != nil {
		return goResolution{}, fmt.Errorf("Go module %s: %w", cfg.goModule, err)
	}
	if info.IsDir() {
		return goResolution{}, fmt.Errorf("Go module path %s is a directory", moduleFile)
	}
	stdoutPath := filepath.Join(runDir, "raw", "checkresolve.stdout.json")
	stderrPath := filepath.Join(runDir, "raw", "checkresolve.stderr.log")
	exitCode, err := runCommand(ctx, cfg.checkresolveCmd, cfg.goModule, goEnv(), stdoutPath, stderrPath)
	if err != nil {
		return goResolution{}, fmt.Errorf("run checkresolve command: %w", err)
	}
	if exitCode != 0 {
		return goResolution{}, fmt.Errorf(
			"checkresolve failed with exit status %d; see %s",
			exitCode, relativeArtifact(runDir, stderrPath),
		)
	}
	data, err := readFileLimited(stdoutPath, maxResolutionBytes)
	if err != nil {
		return goResolution{}, fmt.Errorf("read checkresolve output: %w", err)
	}
	var resolution goResolution
	if err := json.Unmarshal(data, &resolution); err != nil {
		return goResolution{}, fmt.Errorf("checkresolve output is not valid JSON: %w", err)
	}
	return resolution, nil
}

// validateResolution enforces the identity contract before any parity or
// timing run: a known profile, the expected engine module, a matching expected
// profile and a clean pinned local checkout.
func validateResolution(cfg *config, resolution goResolution) error {
	switch resolution.Profile {
	case "upstream", "local":
	default:
		return fmt.Errorf("checkresolve reported unknown profile %q", resolution.Profile)
	}
	if cfg.goProfile != "auto" && cfg.goProfile != resolution.Profile {
		return fmt.Errorf("expected Go profile %q, checkresolve reported %q", cfg.goProfile, resolution.Profile)
	}
	if resolution.Engine.Path != engineModulePath {
		return fmt.Errorf("resolved engine module %q, want %q", resolution.Engine.Path, engineModulePath)
	}
	if strings.TrimSpace(resolution.Engine.Version) == "" {
		return errors.New("resolved engine version is empty")
	}
	if resolution.EngineDirty {
		return errors.New("engine checkout has local modifications; a run requires a clean pinned engine")
	}
	if resolution.Profile == "local" {
		if resolution.Engine.Replace == nil || strings.TrimSpace(resolution.Engine.Replace.Dir) == "" {
			return errors.New("local profile has no resolved directory replacement")
		}
		if strings.TrimSpace(resolution.EngineDir) == "" {
			return errors.New("local profile has no resolved engine directory")
		}
		if !isHexCommit(resolution.EngineRevision) {
			return fmt.Errorf("local profile engine revision %q is not a 40-character hex commit", resolution.EngineRevision)
		}
		return nil
	}
	if resolution.Engine.Replace != nil {
		return errors.New("upstream profile unexpectedly uses a replace directive")
	}
	return nil
}

// gatherIdentity validates and records everything a run must reproduce:
// repository revision, tools, workload hash, Go engine resolution and planned
// commands.
func gatherIdentity(ctx context.Context, cfg *config, runDir string, workload *workload, commands commandsRecord) (identity, error) {
	repository, err := collectRepositoryIdentity(cfg.repoRoot)
	if err != nil {
		return identity{}, err
	}
	resolution, err := checkResolution(ctx, cfg, runDir)
	if err != nil {
		return identity{}, err
	}
	if err := validateResolution(cfg, resolution); err != nil {
		return identity{}, err
	}
	return identity{
		SchemaVersion:     identitySchemaVersion,
		Repository:        repository,
		Tools:             toolVersions(),
		Workload:          workloadIdentityFrom(workload),
		GoEngine:          resolution,
		ExpectedGoProfile: cfg.goProfile,
		GoEnv:             goEnv(),
		Commands:          commands,
	}, nil
}
