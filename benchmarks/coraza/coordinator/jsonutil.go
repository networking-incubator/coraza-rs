// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// decodeStrict decodes one JSON value and rejects unknown object fields and
// trailing values. It is used for manifests, timing documents and parity
// reports so a contract change cannot pass unnoticed.
func decodeStrict(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return fmt.Errorf("trailing data: %w", err)
	}
	return nil
}

// readFileLimited reads at most limit bytes from path and fails when the file
// is larger, so hostile or corrupt inputs cannot exhaust memory.
func readFileLimited(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds the %d-byte limit", path, limit)
	}
	return data, nil
}

// sha256Hex returns the lower-case SHA-256 of data.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// isSHA256Hex reports whether text is a lower-case 64-character hex digest.
func isSHA256Hex(text string) bool {
	return isLowerHex(text, 64)
}

// isHexCommit reports whether text is a lower-case 40-character git revision.
func isHexCommit(text string) bool {
	return isLowerHex(text, 40)
}

// isLowerHex reports whether text has exactly width lower-case hex digits.
func isLowerHex(text string, width int) bool {
	if len(text) != width {
		return false
	}
	for _, char := range []byte(text) {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

// validateCommand rejects commands that cannot be executed safely through the
// shell wrapper. Commands come from operator configuration, not workload data.
func validateCommand(command string) error {
	if strings.TrimSpace(command) == "" {
		return errors.New("command is empty")
	}
	if strings.ContainsRune(command, '\x00') {
		return errors.New("command contains a NUL byte")
	}
	return nil
}

// shellQuote quotes one argument for the POSIX shell used to run commands.
func shellQuote(text string) string {
	return "'" + strings.ReplaceAll(text, "'", `'\''`) + "'"
}

// writeJSON writes one indented JSON document with a trailing newline.
func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

// relativeArtifact returns path relative to the run directory using slashes so
// result documents stay readable and portable.
func relativeArtifact(runDir, path string) string {
	relative, err := filepath.Rel(runDir, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(relative)
}
