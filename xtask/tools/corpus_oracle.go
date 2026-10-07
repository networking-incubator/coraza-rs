// Copyright Coraza Kubernetes Operator contributors.
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

package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	libinjection "github.com/corazawaf/libinjection-go"
)

func main() {
	if len(os.Args) != 2 {
		fail("usage: corpus_oracle <input-file>")
	}
	file, err := os.Open(os.Args[1])
	if err != nil {
		fail(err.Error())
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	writer := bufio.NewWriter(os.Stdout)
	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			fail(err.Error())
		}
		if len(line) > 0 {
			fields := strings.Split(strings.TrimSuffix(line, "\n"), "\t")
			if len(fields) != 2 {
				fail("malformed oracle input row")
			}
			input, err := hex.DecodeString(fields[1])
			if err != nil {
				fail(err.Error())
			}
			detected, fingerprint := libinjection.IsSQLi(string(input))
			result := "0"
			if detected {
				result = "1"
			}
			if _, err := fmt.Fprintf(writer, "%s\t%s\t%x\n", fields[0], result, fingerprint); err != nil {
				fail(err.Error())
			}
		}
		if err == io.EOF {
			break
		}
	}
	if err := writer.Flush(); err != nil {
		fail(err.Error())
	}
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
