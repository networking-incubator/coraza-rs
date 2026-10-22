// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package bench

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
	"strconv"
	"strings"
)

// maxWorkloadFileBytes bounds every workload file the harness reads. The
// shipped cases are tiny; the bound keeps a hostile manifest, case or fixture
// from forcing an unbounded allocation.
const maxWorkloadFileBytes = 64 << 20

// jsonObject keeps every member raw so each field is validated with its exact
// expected type instead of decoding null into a zero value.
type jsonObject map[string]json.RawMessage

// parseJSONDocument decodes exactly one JSON value and rejects trailing data.
func parseJSONDocument(data []byte, context string) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", context, err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("%s has trailing data", context)
		}
		return nil, fmt.Errorf("%s is not valid JSON: %w", context, err)
	}
	return raw, nil
}

// asObject decodes a JSON object, rejects unknown members and checks that every
// required member is present.
func asObject(raw json.RawMessage, context string, required, optional []string) (jsonObject, error) {
	var object jsonObject
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, fmt.Errorf("%s is not an object: %w", context, err)
	}
	if object == nil {
		return nil, fmt.Errorf("%s is not an object", context)
	}
	allowed := make(map[string]struct{}, len(required)+len(optional))
	for _, key := range required {
		allowed[key] = struct{}{}
	}
	for _, key := range optional {
		if _, exists := allowed[key]; exists {
			return nil, fmt.Errorf("%s declares %s twice", context, key)
		}
		allowed[key] = struct{}{}
	}
	for key := range object {
		if _, ok := allowed[key]; !ok {
			return nil, fmt.Errorf("%s has unknown field %s", context, key)
		}
	}
	for _, key := range required {
		if _, ok := object[key]; !ok {
			return nil, fmt.Errorf("%s is missing %s", context, key)
		}
	}
	return object, nil
}

// asMap decodes a JSON object without restricting member names.
func asMap(raw json.RawMessage, context string) (jsonObject, error) {
	var object jsonObject
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, fmt.Errorf("%s is not an object: %w", context, err)
	}
	if object == nil {
		return nil, fmt.Errorf("%s is not an object", context)
	}
	return object, nil
}

// asArray decodes a JSON array. Unlike a nil Go slice, JSON null is rejected.
func asArray(raw json.RawMessage, context string) ([]json.RawMessage, error) {
	var array []json.RawMessage
	if err := json.Unmarshal(raw, &array); err != nil {
		return nil, fmt.Errorf("%s is not an array: %w", context, err)
	}
	if array == nil {
		return nil, fmt.Errorf("%s is not an array", context)
	}
	return array, nil
}

// isNull reports whether the raw value is JSON null.
func isNull(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "null"
}

// stringField decodes a required string.
func stringField(raw json.RawMessage, context string) (string, error) {
	if isNull(raw) {
		return "", fmt.Errorf("%s is not a string", context)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("%s is not a string", context)
	}
	return value, nil
}

// optionalStringField decodes a string that may be absent or null.
func optionalStringField(raw json.RawMessage, context string) (*string, error) {
	if isNull(raw) {
		return nil, nil
	}
	value, err := stringField(raw, context)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

// numberLiteral returns the literal text of a JSON number.
func numberLiteral(raw json.RawMessage, context string) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", fmt.Errorf("%s is not an integer: %w", context, err)
	}
	number, ok := value.(json.Number)
	if !ok {
		return "", fmt.Errorf("%s is not an integer", context)
	}
	return number.String(), nil
}

// uintField decodes a required non-negative integer.
func uintField(raw json.RawMessage, context string) (uint64, error) {
	literal, err := numberLiteral(raw, context)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(literal, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s is not a non-negative integer", context)
	}
	return value, nil
}

// optionalUintField decodes an integer that may be absent or null.
func optionalUintField(raw json.RawMessage, context string) (*uint64, error) {
	if isNull(raw) {
		return nil, nil
	}
	value, err := uintField(raw, context)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

// intField decodes a required signed integer.
func intField(raw json.RawMessage, context string) (int64, error) {
	literal, err := numberLiteral(raw, context)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseInt(literal, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s is not an integer", context)
	}
	return value, nil
}

// boolField decodes a required boolean.
func boolField(raw json.RawMessage, context string) (bool, error) {
	if isNull(raw) {
		return false, fmt.Errorf("%s is not a boolean", context)
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, fmt.Errorf("%s is not a boolean", context)
	}
	return value, nil
}

// readFileBounded reads a file with a fixed upper bound.
func readFileBounded(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()
	data, err := io.ReadAll(io.LimitReader(file, maxWorkloadFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxWorkloadFileBytes {
		return nil, fmt.Errorf("%s exceeds the %d-byte limit", path, maxWorkloadFileBytes)
	}
	return data, nil
}

// relativePath rejects absolute paths and . or .. components.
func relativePath(text, context string) (string, error) {
	if text == "" {
		return "", fmt.Errorf("%s is empty", context)
	}
	if filepath.IsAbs(text) {
		return "", fmt.Errorf("%s must be relative: %s", context, text)
	}
	for _, part := range strings.Split(filepath.ToSlash(text), "/") {
		if part == "." || part == ".." {
			return "", fmt.Errorf("%s must not contain . or .. components: %s", context, text)
		}
	}
	return text, nil
}

// sha256Hex returns the lower-case hexadecimal SHA-256 of data.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// isSHA256 reports whether text is a lower-case SHA-256 hex string.
func isSHA256(text string) bool {
	if len(text) != 64 {
		return false
	}
	for i := 0; i < len(text); i++ {
		character := text[i]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// isHex40 reports whether text is a 40-character lower-case hex commit.
func isHex40(text string) bool {
	if len(text) != 40 {
		return false
	}
	for i := 0; i < len(text); i++ {
		character := text[i]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
