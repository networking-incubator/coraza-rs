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
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWriteReflectResponse(t *testing.T) {
	writer := httptest.NewRecorder()
	writeReflectResponse(writer, []byte(`{"status":418,"headers":{"X-Test":"yes"},"body":"reflected"}`))
	if writer.Code != 418 || writer.Body.String() != "reflected" || writer.Header().Get("X-Test") != "yes" {
		t.Fatalf("response = %d %q %v", writer.Code, writer.Body.String(), writer.Header())
	}
	if got := writer.Header().Get("Content-Type"); got != "text/plain" {
		t.Fatalf("Content-Type = %q, want text/plain", got)
	}
}

func TestWriteReflectResponseInvalidJSONUsesDefault(t *testing.T) {
	writer := httptest.NewRecorder()
	writeReflectResponse(writer, []byte("not-json"))
	if writer.Code != 200 || writer.Body.String() != "OK" {
		t.Fatalf("response = %d %q, want 200 OK", writer.Code, writer.Body.String())
	}
}

func TestSlowResponseRecordsClientCancellation(t *testing.T) {
	backend := &backend{counts: make(map[string]int), cancellations: make(map[string]int)}
	server := httptest.NewServer(backend)
	defer server.Close()

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/slow-response", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	request.Close = true
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	if _, err := io.CopyN(io.Discard, response.Body, 1); err != nil {
		t.Fatalf("read initial response byte: %v", err)
	}
	_ = response.Body.Close()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		backend.mu.Lock()
		count := backend.cancellations["/slow-response"]
		backend.mu.Unlock()
		if count == 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("backend did not observe the cancelled response stream")
}
