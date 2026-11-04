package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const largeBodySize = 1024*1024 + 1

type backend struct {
	mu            sync.Mutex
	counts        map[string]int
	cancellations map[string]int
}

func (b *backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/__stats" {
		b.writeStats(w, r)
		return
	}
	b.mu.Lock()
	b.counts[r.URL.Path]++
	b.mu.Unlock()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "could not read request", http.StatusBadRequest)
		return
	}
	switch {
	case r.URL.Path == "/reflect":
		writeReflectResponse(w, body)
	case r.URL.Path == "/slow-response":
		b.writeSlowResponse(w, r)
	case r.URL.Path == "/echo":
		w.Header().Set("Content-Type", "application/octet-stream")
		if trailer := r.Trailer.Get("X-Client-Trailer"); trailer != "" {
			w.Header().Set("X-Client-Trailer-Seen", trailer)
		}
		writeBody(w, body)
	case r.URL.Path == "/response-deny":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Upstream-Secret", "upstream-header-marker")
		w.Header().Set("Set-Cookie", "upstream-secret=secret-cookie")
		writeBody(w, []byte("secret upstream response body"))
	case r.URL.Path == "/response-redirect":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Upstream-Secret", "upstream-header-marker")
		writeBody(w, []byte("response-redirect"))
	case r.URL.Path == "/response-redirect-crlf":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Upstream-Secret", "upstream-header-marker")
		writeBody(w, []byte("response-crlf-redirect\r\nSet-Cookie: injected=1"))
	case r.URL.Path == "/response-partial":
		w.Header().Set("Content-Type", "text/plain")
		writeBody(w, append(bytes.Repeat([]byte{'x'}, 32), []byte("partial-marker")...))
	case r.URL.Path == "/response-trailer-budget":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Add("Trailer", "X-Large-Trailer")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream trailer body"))
		w.Header().Set("X-Large-Trailer", strings.Repeat("a", 64*1024+1))
	case r.URL.Path == "/response-trailers":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Add("Trailer", "X-Backend-Trailer")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("trailer response"))
		w.Header().Set("X-Backend-Trailer", "passed")
	case r.URL.Path == "/response-trailers-deny":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Upstream-Secret", "upstream-header-marker")
		w.Header().Add("Trailer", "X-Backend-Trailer")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("secret trailer response"))
		w.Header().Set("X-Backend-Trailer", "upstream-trailer-marker")
	case r.URL.Path == "/empty":
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusOK)
	case r.URL.Path == "/large-uninspectable":
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Large-Probe", "preserved")
		writeBody(w, bytes.Repeat([]byte{'z'}, largeBodySize))
	case r.URL.Path == "/multi-frame-response":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Large-Probe", "inspectable")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "response flushing unavailable", http.StatusInternalServerError)
			return
		}
		for range 16 {
			_, _ = w.Write(bytes.Repeat([]byte{'a'}, 16*1024))
			flusher.Flush()
			time.Sleep(5 * time.Millisecond)
		}
	case r.URL.Path == "/large-response":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Upstream-Secret", "upstream-header-marker")
		writeBody(w, bytes.Repeat([]byte{'z'}, largeBodySize))
	case r.URL.Path == "/large-header-deny":
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Deny-Response", "yes")
		body := bytes.Repeat([]byte{'z'}, largeBodySize)
		copy(body[len(body)-len("LEAK-MARKER"):], "LEAK-MARKER")
		writeBody(w, body)
	case strings.HasPrefix(r.URL.Path, "/bytes/"):
		size, parseErr := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/bytes/"))
		if parseErr != nil || size < 0 || size > largeBodySize {
			http.Error(w, "invalid body size", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		writeBody(w, bytes.Repeat([]byte{'a'}, size))
	default:
		w.Header().Set("Content-Type", "text/plain")
		writeBody(w, []byte("backend received "+r.URL.Path+" "+string(body)))
	}
}

func writeReflectResponse(w http.ResponseWriter, body []byte) {
	var spec struct {
		Status      int               `json:"status"`
		Headers     map[string]string `json:"headers"`
		Body        *string           `json:"body"`
		EncodedBody *string           `json:"encodedBody"`
	}
	if err := json.Unmarshal(body, &spec); err != nil {
		w.Header().Set("Content-Type", "text/plain")
		writeBody(w, []byte("OK"))
		return
	}
	responseBody := []byte{}
	if spec.Body != nil {
		responseBody = []byte(*spec.Body)
	} else if spec.EncodedBody != nil {
		decoded, err := base64.StdEncoding.DecodeString(*spec.EncodedBody)
		if err == nil {
			responseBody = decoded
		}
	}
	for name, value := range spec.Headers {
		w.Header().Set(name, value)
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "text/plain")
	}
	status := spec.Status
	if status < 100 || status > 599 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(responseBody)
}

func (b *backend) writeStats(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if path := r.URL.Query().Get("cancelled"); path != "" {
		_, _ = fmt.Fprint(w, b.cancellations[path])
		return
	}
	if path := r.URL.Query().Get("path"); path != "" {
		_, _ = fmt.Fprint(w, b.counts[path])
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(b.counts)
}

func (b *backend) writeSlowResponse(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming is unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	chunk := bytes.Repeat([]byte{'s'}, 16*1024)
	for range 32 {
		select {
		case <-r.Context().Done():
			b.recordCancellation(r.URL.Path)
			return
		default:
		}
		if _, err := w.Write(chunk); err != nil {
			b.recordCancellation(r.URL.Path)
			return
		}
		flusher.Flush()
		time.Sleep(10 * time.Millisecond)
	}
}

func (b *backend) recordCancellation(path string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cancellations[path]++
}

func writeBody(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}

func main() {
	server := &http.Server{
		Addr:    ":3000",
		Handler: &backend{counts: make(map[string]int), cancellations: make(map[string]int)},
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("backend listening on %s", listener.Addr())
	log.Fatal(server.Serve(listener))
}
