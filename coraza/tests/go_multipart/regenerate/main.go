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

// Command regenerate runs Go Coraza's multipart body processor on the bodies of
// ../cases.json and writes the same file with what the processor published.
//
// The module path puts this program under Go Coraza's `internal/`, which is how it
// may import the processor and the transaction variables it fills; see ../README.md.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"regexp"
	"sort"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/bodyprocessors"
	"github.com/corazawaf/coraza/v3/internal/collections"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

const contentType = "multipart/form-data; boundary=b"

type published struct {
	Error  string `json:"error"`
	Strict bool   `json:"strict"`
	// Stopped is whether the processor stopped at a part that cannot be read to its end, and this engine publishes more
	// than the processor did: it returned the error of reading the part, or it read no further part after a part that
	// ended inside its body while a part follows.
	Stopped      bool                   `json:"stopped"`
	CombinedSize string                 `json:"combined_size"`
	Collections  map[string][][2]string `json:"collections"`
	TmpFiles     []string               `json:"tmp_files"`
}

type fixtureCase struct {
	Name string    `json:"name"`
	Cut  bool      `json:"cut"`
	Body string    `json:"body"`
	Go   published `json:"go"`
	// Raw is what the processor publishes for the same body with its Content-Transfer-Encoding headers renamed, so that
	// no part is decoded: the parts as they were sent, which is what this engine publishes besides the decoded ones.
	Raw published `json:"raw"`
}

// encodingHeader matches the name of the header that selects a part's transfer encoding, in any case.
var encodingHeader = regexp.MustCompile(`(?i)content-transfer-encoding`)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: regenerate <cases.json> <scratch dir for temporary uploads>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	check(err)
	var cases []fixtureCase
	check(json.Unmarshal(raw, &cases))
	processor, err := bodyprocessors.GetBodyProcessor("multipart")
	check(err)

	var out bytes.Buffer
	out.WriteString("[\n")
	for i := range cases {
		body, err := hex.DecodeString(cases[i].Body)
		check(err)
		cases[i].Go = run(processor, body, cases[i].Cut, os.Args[2])
		// Same length, so no offset in the body moves, and a name that is no header Go decodes by.
		cases[i].Raw = run(processor, encodingHeader.ReplaceAll(body, []byte("Content-Transfer-Encodinx")), cases[i].Cut, os.Args[2])
		line, err := json.Marshal(cases[i])
		check(err)
		out.Write(line)
		if i+1 < len(cases) {
			out.WriteString(",")
		}
		out.WriteString("\n")
	}
	out.WriteString("]\n")
	check(os.WriteFile(os.Args[1], out.Bytes(), 0o644))
}

// run feeds body to the processor. A body the request body limit cut carries INBOUND_DATA_ERROR.
func run(processor plugintypes.BodyProcessor, body []byte, cut bool, scratch string) published {
	variables := corazawaf.NewTransactionVariables()
	if cut {
		variables.InboundDataError().(*collections.Single).Set("1")
	}
	store, err := os.MkdirTemp(scratch, "upload")
	check(err)
	defer os.RemoveAll(store)
	runErr := processor.ProcessRequest(bytes.NewReader(body), variables, plugintypes.BodyProcessorOptions{Mime: contentType, StoragePath: store})

	result := published{
		Strict:       variables.MultipartStrictError().Get() == "1",
		CombinedSize: variables.FilesCombinedSize().Get(),
		Collections:  map[string][][2]string{},
		TmpFiles:     []string{},
	}
	if runErr != nil {
		result.Error = runErr.Error()
	}
	result.Stopped = stopped(body)
	for name, c := range map[string]collection.Collection{
		"args_post":    variables.ArgsPost(),
		"files":        variables.Files(),
		"files_names":  variables.FilesNames(),
		"files_sizes":  variables.FilesSizes(),
		"part_headers": variables.MultipartPartHeaders(),
		"mp_name":      variables.MultipartName(),
		"mp_filename":  variables.MultipartFilename(),
	} {
		rows := [][2]string{}
		for _, match := range c.FindAll() {
			rows = append(rows, [2]string{hex.EncodeToString([]byte(match.Key())), hex.EncodeToString([]byte(match.Value()))})
		}
		sort.Slice(rows, func(a, b int) bool {
			if rows[a][0] != rows[b][0] {
				return rows[a][0] < rows[b][0]
			}
			return rows[a][1] < rows[b][1]
		})
		result.Collections[name] = rows
	}
	for _, match := range variables.FilesTmpNames().FindAll() {
		content, err := os.ReadFile(match.Value())
		check(err)
		result.TmpFiles = append(result.TmpFiles, hex.EncodeToString(content))
	}
	sort.Strings(result.TmpFiles)
	return result
}

// stopped reports whether reading a part of body to its end fails with an error that the processor returns, or with
// io.ErrUnexpectedEOF while a part follows, which the processor never reads: the two ways it stops at a part.
func stopped(body []byte) bool {
	reader := multipart.NewReader(bytes.NewReader(body), "b")
	failed := false
	for {
		part, err := reader.NextPart()
		if err != nil {
			return false
		}
		if failed {
			return true
		}
		if _, err := io.Copy(io.Discard, part); err != nil {
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				return true
			}
			failed = true
		}
	}
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
