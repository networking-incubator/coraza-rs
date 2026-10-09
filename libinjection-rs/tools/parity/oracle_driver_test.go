// Copyright 2026 Coraza Kubernetes Operator contributors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package libinjection

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestBinaryOracle is copied into a temporary checkout of the pinned Go
// package by tools/parity/go-oracle. It is a data emitter, not an upstream
// behavior change: every reported result comes from existing package APIs or
// parser state.
func TestBinaryOracle(t *testing.T) {
	outputPath := os.Getenv("LIBINJECTION_ORACLE_OUTPUT")
	if outputPath == "" {
		t.Fatal("LIBINJECTION_ORACLE_OUTPUT is required")
	}
	output, err := os.Create(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()

	writer := bufio.NewWriterSize(output, 128*1024)
	defer writer.Flush()

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 128*1024*1024)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "\t", 2)
		if len(parts) != 2 || parts[0] == "" {
			t.Fatalf("malformed oracle request")
		}
		input, decodeErr := hex.DecodeString(parts[1])
		if decodeErr != nil {
			t.Fatalf("invalid input hex for %q", parts[0])
		}

		fields := oracleRecord(input)
		fields[0] = parts[0]
		if _, err := fmt.Fprintln(writer, strings.Join(fields, "\t")); err != nil {
			t.Fatal(err)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

var oracleSQLModes = [6]int{
	sqliFlagQuoteNone | sqliFlagSQLAnsi,
	sqliFlagQuoteNone | sqliFlagSQLMysql,
	sqliFlagQuoteSingle | sqliFlagSQLAnsi,
	sqliFlagQuoteSingle | sqliFlagSQLMysql,
	sqliFlagQuoteDouble | sqliFlagSQLAnsi,
	sqliFlagQuoteDouble | sqliFlagSQLMysql,
}

var oracleHTMLContexts = [5]int{
	html5FlagsDataState,
	html5FlagsValueNoQuote,
	html5FlagsValueSingleQuote,
	html5FlagsValueDoubleQuote,
	html5FlagsValueBackQuote,
}

func oracleRecord(input []byte) []string {
	fields := make([]string, 22)
	var errors []string
	safeOracleField(fields, &errors, 2, "sql-verdict", func() {
		sqli, _ := IsSQLi(string(input))
		if sqli {
			fields[2] = "1"
		} else {
			fields[2] = "0"
		}
	})
	safeOracleField(fields, &errors, 3, "sql-verdict", func() {
		_, fingerprint := IsSQLi(string(input))
		fields[3] = hex.EncodeToString([]byte(fingerprint)) + ":" + strconv.FormatInt(int64(len(fingerprint)), 16)
	})

	for index, flags := range oracleSQLModes {
		safeOracleField(fields, &errors, 4+index, fmt.Sprintf("sql-raw-flags-%d", flags), func() {
			state := new(sqliState)
			sqliInit(state, string(input), flags)
			var tokens []string
			for state.tokenize() {
				tokens = append(tokens, oracleSQLToken(state.current))
			}
			fields[4+index] = oracleSQLStats(state) + ";" + strings.Join(tokens, ";")
		})

		safeOracleField(fields, &errors, 10+index, fmt.Sprintf("sql-fold-flags-%d", flags), func() {
			state := new(sqliState)
			sqliInit(state, string(input), flags)
			foldedCount := state.fold()
			tokens := make([]string, 0, foldedCount)
			for i := 0; i < foldedCount; i++ {
				tokens = append(tokens, oracleSQLToken(&state.tokenVec[i]))
			}
			fields[10+index] = oracleSQLStats(state) + ";" + strings.Join(tokens, ";")
		})
	}

	for index, context := range oracleHTMLContexts {
		safeOracleField(fields, &errors, 16+index, fmt.Sprintf("html5-context-%d", context), func() {
			state := new(h5State)
			state.init(string(input), context)
			var tokens []string
			for state.next() {
				value := []byte(state.tokenStart[:state.tokenLen])
				tokens = append(tokens, strconv.Itoa(state.tokenType)+":"+strconv.Itoa(state.tokenLen)+":"+hex.EncodeToString(value))
			}
			fields[16+index] = strings.Join(tokens, ";")
		})
	}

	safeOracleField(fields, &errors, 21, "xss-verdict", func() {
		if IsXSS(string(input)) {
			fields[21] = "1"
		} else {
			fields[21] = "0"
		}
	})
	fields[1] = strings.Join(errors, ";")
	return fields
}

func safeOracleField(fields []string, errors *[]string, index int, stage string, run func()) {
	defer func() {
		if recovered := recover(); recovered != nil {
			message := fmt.Sprintf("%s: %v", stage, recovered)
			*errors = append(*errors, strconv.Itoa(index)+"="+hex.EncodeToString([]byte(message)))
		}
	}()
	run()
}

func oracleSQLStats(state *sqliState) string {
	return strconv.Itoa(state.statsTokens) + "," +
		strconv.Itoa(state.statsFolds) + "," +
		strconv.Itoa(state.statsCommentDDX) + "," +
		strconv.Itoa(state.statsCommentHash)
}

func oracleSQLToken(token *sqliToken) string {
	value := token.val
	if token.len < len(value) {
		value = value[:token.len]
	}
	return fmt.Sprintf("%02x:%d:%d:%d:%02x:%02x:%s",
		token.category,
		token.pos,
		token.len,
		token.count,
		token.strOpen,
		token.strClose,
		hex.EncodeToString([]byte(value)),
	)
}
