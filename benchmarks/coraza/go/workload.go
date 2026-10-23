// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package bench

// Workload loading and validation for the shared Go-versus-Rust cases. The
// invariants mirror the Rust loader in
// coraza/benches/coraza_workload/driver.rs: every case, fixture and policy is
// validated once, before any transaction runs.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/corazawaf/coraza/v3/types/variables"
)

const (
	// schemaVersion is the only case and manifest schema version this driver
	// understands.
	schemaVersion = 1
	// maxCaptureIndex is the highest TX index a Coraza capture can occupy.
	maxCaptureIndex = 9
)

// normalizations are the nondeterminism names the case schema permits.
var normalizations = map[string]struct{}{
	"timestamps":       {},
	"generated_ids":    {},
	"temporary_paths":  {},
	"audit_boundaries": {},
	"header_order":     {},
}

// resolvedBytes is a decoded inline value or a validated fixture range.
type resolvedBytes struct {
	data []byte
	// fixtureSHA is the hash of the referenced fixture file, when one was read.
	fixtureSHA *string
}

// fixtureTracker records the first fixture hash in canonical field order.
type fixtureTracker struct {
	first *string
}

func (t *fixtureTracker) track(hash *string) {
	if t.first == nil && hash != nil {
		t.first = hash
	}
}

// caseHeader is one header occurrence. Order and repeats are significant.
type caseHeader struct {
	name  string
	value []byte
}

// caseRequest is the request as supplied by the connector.
type caseRequest struct {
	method     string
	uri        []byte
	protocol   string
	headers    []caseHeader
	body       []byte
	chunkCount int
}

// caseResponse is the response as supplied by the connector.
type caseResponse struct {
	status     int
	protocol   string
	headers    []caseHeader
	body       []byte
	chunkCount int
}

// caseConnection is the connection metadata replayed by the driver.
type caseConnection struct {
	remoteAddr string
	remotePort int
	localAddr  string
	localPort  int
}

// phaseCall is one ordered lifecycle call.
type phaseCall struct {
	call       string
	phase      int
	chunkIndex *int
}

// expectedMatch is one expected rule match.
type expectedMatch struct {
	ruleID   int64
	phase    int
	variable string
	key      *string
	value    []byte
}

// expectedInterruption is one expected effective interruption.
type expectedInterruption struct {
	ruleID int64
	action string
	status int64
	data   []byte
}

// expectedCapture is one expected TX capture.
type expectedCapture struct {
	index int
	value []byte
}

// expectedCollection is one expected collection value.
type expectedCollection struct {
	variable string
	key      *string
	value    []byte
	// parsed is the engine variable used to read the collection.
	parsed variables.RuleVariable
}

// expectedOutcome is the case's expected observable outcome.
type expectedOutcome struct {
	matches       []expectedMatch
	interruptions []expectedInterruption
	captures      []expectedCapture
	scores        map[string]int64
	flags         map[string]string
	collections   []expectedCollection
}

// workloadCase is one fully validated case.
type workloadCase struct {
	id         string
	connection caseConnection
	request    caseRequest
	response   caseResponse
	secLang    string
	phaseCalls []phaseCall
	expected   expectedOutcome
}

// PreparedCase is one validated case with its policy compiled once.
type PreparedCase struct {
	// ID is the case identifier from the manifest.
	ID string
	// request is the lifecycle input derived from the case.
	request Request
	// expected is the case's expected outcome, used by CheckExpected.
	expected expectedOutcome
	// engine owns the compiled policy.
	engine *Engine
}

// Close releases resources cached by the case's compiled policy.
func (p *PreparedCase) Close() error {
	return p.engine.Close()
}

// WorkloadInfo identifies a loaded workload. ManifestSHA256 is the lower-case
// SHA-256 of the exact manifest file bytes.
type WorkloadInfo struct {
	ID             string
	ManifestSHA256 string
}

// LoadWorkload reads the manifest, verifies every case and fixture hash and
// compiles every policy once.
func LoadWorkload(root string) ([]*PreparedCase, error) {
	cases, _, err := LoadWorkloadWithInfo(root)
	return cases, err
}

// LoadWorkloadWithInfo is LoadWorkload plus the manifest identity the timing
// document records. The manifest and every case are still read and validated
// once.
func LoadWorkloadWithInfo(root string) ([]*PreparedCase, WorkloadInfo, error) {
	manifestPath := filepath.Join(root, "manifest.json")
	manifestBytes, err := readFileBounded(manifestPath)
	if err != nil {
		return nil, WorkloadInfo{}, fmt.Errorf("cannot read %s: %w", manifestPath, err)
	}
	raw, err := parseJSONDocument(manifestBytes, "manifest")
	if err != nil {
		return nil, WorkloadInfo{}, err
	}
	object, err := asObject(
		raw,
		"manifest",
		[]string{"schema_version", "workload_id", "description", "case_schema", "cases"},
		nil,
	)
	if err != nil {
		return nil, WorkloadInfo{}, err
	}
	if err := checkSchemaVersion(object["schema_version"], "manifest"); err != nil {
		return nil, WorkloadInfo{}, err
	}
	workloadID, err := stringField(object["workload_id"], "manifest workload_id")
	if err != nil {
		return nil, WorkloadInfo{}, err
	}
	if workloadID == "" {
		return nil, WorkloadInfo{}, fmt.Errorf("manifest workload_id is empty")
	}
	if _, err := stringField(object["description"], "manifest description"); err != nil {
		return nil, WorkloadInfo{}, err
	}
	if _, err := stringField(object["case_schema"], "manifest case_schema"); err != nil {
		return nil, WorkloadInfo{}, err
	}
	entries, err := asArray(object["cases"], "manifest cases")
	if err != nil {
		return nil, WorkloadInfo{}, err
	}
	if len(entries) == 0 {
		return nil, WorkloadInfo{}, fmt.Errorf("manifest has no cases")
	}

	seen := make(map[string]struct{}, len(entries))
	caseIDs := make(map[string]string, len(entries))
	prepared := make([]*PreparedCase, 0, len(entries))
	for index, entry := range entries {
		entryContext := fmt.Sprintf("manifest case %d", index)
		entry, err := asObject(entry, entryContext, []string{"path", "sha256"}, nil)
		if err != nil {
			return nil, WorkloadInfo{}, err
		}
		path, err := stringField(entry["path"], entryContext+" path")
		if err != nil {
			return nil, WorkloadInfo{}, err
		}
		if _, err := relativePath(path, entryContext+" path"); err != nil {
			return nil, WorkloadInfo{}, err
		}
		if _, duplicate := seen[path]; duplicate {
			return nil, WorkloadInfo{}, fmt.Errorf("%s repeats case path %s", entryContext, path)
		}
		seen[path] = struct{}{}
		declared, err := stringField(entry["sha256"], entryContext+" sha256")
		if err != nil {
			return nil, WorkloadInfo{}, err
		}
		if !isSHA256(declared) {
			return nil, WorkloadInfo{}, fmt.Errorf("%s sha256 is malformed", entryContext)
		}
		casePath := filepath.Join(root, filepath.FromSlash(path))
		source, err := readFileBounded(casePath)
		if err != nil {
			return nil, WorkloadInfo{}, fmt.Errorf("cannot read %s: %w", casePath, err)
		}
		if actual := sha256Hex(source); actual != declared {
			return nil, WorkloadInfo{}, fmt.Errorf("case %s has SHA-256 %s, not %s", casePath, actual, declared)
		}
		parsed, err := parseCaseBytes(source, root)
		if err != nil {
			return nil, WorkloadInfo{}, err
		}
		if firstPath, duplicate := caseIDs[parsed.id]; duplicate {
			return nil, WorkloadInfo{}, fmt.Errorf(
				"%s: duplicate case id %q in %s and %s",
				entryContext, parsed.id, firstPath, path,
			)
		}
		caseIDs[parsed.id] = path
		engine, err := New(parsed.secLang)
		if err != nil {
			return nil, WorkloadInfo{}, fmt.Errorf("case %s: %w", parsed.id, err)
		}
		prepared = append(prepared, &PreparedCase{
			ID:       parsed.id,
			request:  parsed.requestInput(),
			expected: parsed.expected,
			engine:   engine,
		})
	}
	return prepared, WorkloadInfo{ID: workloadID, ManifestSHA256: sha256Hex(manifestBytes)}, nil
}

// requestInput maps a validated case onto the lifecycle request without
// normalizing any byte, header or protocol text.
func (c *workloadCase) requestInput() Request {
	return Request{
		ClientIP:         c.connection.remoteAddr,
		ClientPort:       c.connection.remotePort,
		ServerIP:         c.connection.localAddr,
		ServerPort:       c.connection.localPort,
		Method:           c.request.method,
		URI:              string(c.request.uri),
		HTTPVersion:      c.request.protocol,
		RequestHeaders:   headerPairs(c.request.headers),
		RequestBody:      c.request.body,
		ResponseCode:     c.response.status,
		ResponseProtocol: c.response.protocol,
		ResponseHeaders:  headerPairs(c.response.headers),
		ResponseBody:     c.response.body,
	}
}

// headerPairs converts validated headers to the lifecycle representation.
func headerPairs(headers []caseHeader) [][2]string {
	pairs := make([][2]string, len(headers))
	for index, header := range headers {
		pairs[index] = [2]string{header.name, string(header.value)}
	}
	return pairs
}

// checkSchemaVersion requires the schema version this driver understands.
func checkSchemaVersion(raw []byte, context string) error {
	version, err := uintField(raw, context+" schema_version")
	if err != nil {
		return err
	}
	if version != schemaVersion {
		return fmt.Errorf("%s schema_version must be %d", context, schemaVersion)
	}
	return nil
}

// parseCaseBytes validates one case against the supported schema subset.
func parseCaseBytes(source []byte, corpusRoot string) (*workloadCase, error) {
	raw, err := parseJSONDocument(source, "case")
	if err != nil {
		return nil, err
	}
	object, err := asObject(raw, "case", []string{
		"schema_version",
		"case_id",
		"fixture_sha256",
		"reference",
		"connection",
		"request",
		"response",
		"processor",
		"phase_calls",
		"expected",
		"normalize",
	}, nil)
	if err != nil {
		return nil, err
	}
	if err := checkSchemaVersion(object["schema_version"], "case"); err != nil {
		return nil, err
	}
	caseID, err := stringField(object["case_id"], "case_id")
	if err != nil {
		return nil, err
	}
	if caseID == "" {
		return nil, fmt.Errorf("case_id is empty")
	}
	context := "case " + caseID
	if err := parseReference(object["reference"], context); err != nil {
		return nil, err
	}
	connection, err := parseConnection(object["connection"], context)
	if err != nil {
		return nil, err
	}
	tracker := &fixtureTracker{}
	request, err := parseRequest(object["request"], corpusRoot, context, tracker)
	if err != nil {
		return nil, err
	}
	response, err := parseResponse(object["response"], corpusRoot, context, tracker)
	if err != nil {
		return nil, err
	}
	secLang, err := parseProcessor(object["processor"], corpusRoot, context, tracker)
	if err != nil {
		return nil, err
	}
	phaseCalls, err := parsePhaseCalls(object["phase_calls"], request, response, context)
	if err != nil {
		return nil, err
	}
	expected, err := parseExpected(object["expected"], corpusRoot, context)
	if err != nil {
		return nil, err
	}
	if err := parseNormalize(object["normalize"], context); err != nil {
		return nil, err
	}
	if err := checkFixtureSHA(object["fixture_sha256"], request, response, tracker, context); err != nil {
		return nil, err
	}
	return &workloadCase{
		id:         caseID,
		connection: connection,
		request:    request,
		response:   response,
		secLang:    secLang,
		phaseCalls: phaseCalls,
		expected:   expected,
	}, nil
}

// parseReference validates the pinned reference block.
func parseReference(raw json.RawMessage, context string) error {
	reference, err := asObject(raw, context+" reference", []string{"profile", "go_commit", "rust_commit"}, nil)
	if err != nil {
		return err
	}
	profile, err := stringField(reference["profile"], context+" reference profile")
	if err != nil {
		return err
	}
	if profile == "" {
		return fmt.Errorf("%s reference profile is empty", context)
	}
	for _, field := range []string{"go_commit", "rust_commit"} {
		commit, err := stringField(reference[field], context+" reference "+field)
		if err != nil {
			return err
		}
		if !isHex40(commit) {
			return fmt.Errorf("%s reference %s is not a 40-character hex commit", context, field)
		}
	}
	return nil
}

// parseConnection parses connection metadata.
func parseConnection(raw json.RawMessage, context string) (caseConnection, error) {
	object, err := asObject(raw, context+" connection", []string{
		"remote_addr",
		"remote_port",
		"local_addr",
		"local_port",
		"tls",
	}, []string{"tls_version"})
	if err != nil {
		return caseConnection{}, err
	}
	if _, err := boolField(object["tls"], context+" connection tls"); err != nil {
		return caseConnection{}, err
	}
	if rawVersion, ok := object["tls_version"]; ok {
		if _, err := optionalStringField(rawVersion, context+" connection tls_version"); err != nil {
			return caseConnection{}, err
		}
	}
	connection := caseConnection{}
	if connection.remoteAddr, err = stringField(object["remote_addr"], context+" connection remote_addr"); err != nil {
		return caseConnection{}, err
	}
	if connection.localAddr, err = stringField(object["local_addr"], context+" connection local_addr"); err != nil {
		return caseConnection{}, err
	}
	if connection.remotePort, err = portField(object["remote_port"], context+" remote_port"); err != nil {
		return caseConnection{}, err
	}
	if connection.localPort, err = portField(object["local_port"], context+" local_port"); err != nil {
		return caseConnection{}, err
	}
	return connection, nil
}

// portField parses a TCP port.
func portField(raw json.RawMessage, context string) (int, error) {
	value, err := uintField(raw, context)
	if err != nil {
		return 0, err
	}
	if value > math.MaxUint16 {
		return 0, fmt.Errorf("%s is out of range", context)
	}
	return int(value), nil
}

// parseHeaders parses ordered header occurrences.
func parseHeaders(raw json.RawMessage, corpusRoot, context string, tracker *fixtureTracker) ([]caseHeader, error) {
	items, err := asArray(raw, context)
	if err != nil {
		return nil, err
	}
	headers := make([]caseHeader, 0, len(items))
	for index, item := range items {
		itemContext := fmt.Sprintf("%s header %d", context, index)
		object, err := asObject(item, itemContext, []string{"name", "value"}, nil)
		if err != nil {
			return nil, err
		}
		name, err := stringField(object["name"], itemContext+" name")
		if err != nil {
			return nil, err
		}
		if name == "" {
			return nil, fmt.Errorf("%s name is empty", itemContext)
		}
		value, err := resolveBytes(object["value"], corpusRoot, itemContext)
		if err != nil {
			return nil, err
		}
		tracker.track(value.fixtureSHA)
		headers = append(headers, caseHeader{name: name, value: value.data})
	}
	return headers, nil
}

// parseChunkCount validates chunk boundaries and returns how many chunks cover
// the body.
func parseChunkCount(raw json.RawMessage, bodyLen int, context string) (int, error) {
	items, err := asArray(raw, context)
	if err != nil {
		return 0, err
	}
	next := uint64(0)
	for index, item := range items {
		itemContext := fmt.Sprintf("%s chunk %d", context, index)
		object, err := asObject(item, itemContext, []string{"offset", "length"}, nil)
		if err != nil {
			return 0, err
		}
		offset, err := uintField(object["offset"], itemContext+" offset")
		if err != nil {
			return 0, err
		}
		length, err := uintField(object["length"], itemContext+" length")
		if err != nil {
			return 0, err
		}
		if offset != next {
			return 0, fmt.Errorf("%s chunk offsets are not contiguous at chunk %d", context, index)
		}
		if length > math.MaxUint64-offset {
			return 0, fmt.Errorf("%s chunk length overflows", context)
		}
		next = offset + length
		if next > uint64(bodyLen) {
			return 0, fmt.Errorf("%s chunk %d extends past the body", context, index)
		}
	}
	if next != uint64(bodyLen) {
		return 0, fmt.Errorf("%s chunks cover %d of %d body bytes", context, next, bodyLen)
	}
	return len(items), nil
}

// parseRequest parses the request block.
func parseRequest(raw json.RawMessage, corpusRoot, context string, tracker *fixtureTracker) (caseRequest, error) {
	object, err := asObject(raw, context+" request", []string{
		"method",
		"uri",
		"protocol",
		"headers",
		"body",
		"chunks",
	}, nil)
	if err != nil {
		return caseRequest{}, err
	}
	requestContext := context + " request"
	method, err := stringField(object["method"], requestContext+" method")
	if err != nil {
		return caseRequest{}, err
	}
	protocol, err := stringField(object["protocol"], requestContext+" protocol")
	if err != nil {
		return caseRequest{}, err
	}
	if method == "" || protocol == "" {
		return caseRequest{}, fmt.Errorf("%s method or protocol is empty", requestContext)
	}
	uri, err := resolveBytes(object["uri"], corpusRoot, requestContext)
	if err != nil {
		return caseRequest{}, err
	}
	tracker.track(uri.fixtureSHA)
	if !utf8.Valid(uri.data) {
		return caseRequest{}, fmt.Errorf("%s URI is not UTF-8; the Rust public API requires text", requestContext)
	}
	headers, err := parseHeaders(object["headers"], corpusRoot, requestContext, tracker)
	if err != nil {
		return caseRequest{}, err
	}
	body, err := resolveBytes(object["body"], corpusRoot, requestContext)
	if err != nil {
		return caseRequest{}, err
	}
	tracker.track(body.fixtureSHA)
	chunkCount, err := parseChunkCount(object["chunks"], len(body.data), requestContext)
	if err != nil {
		return caseRequest{}, err
	}
	return caseRequest{
		method:     method,
		uri:        uri.data,
		protocol:   protocol,
		headers:    headers,
		body:       body.data,
		chunkCount: chunkCount,
	}, nil
}

// parseResponse parses the response block.
func parseResponse(raw json.RawMessage, corpusRoot, context string, tracker *fixtureTracker) (caseResponse, error) {
	object, err := asObject(raw, context+" response", []string{
		"status",
		"protocol",
		"headers",
		"body",
		"chunks",
	}, nil)
	if err != nil {
		return caseResponse{}, err
	}
	responseContext := context + " response"
	status, err := uintField(object["status"], responseContext+" status")
	if err != nil {
		return caseResponse{}, err
	}
	if status < 100 || status > 999 {
		return caseResponse{}, fmt.Errorf("%s status is out of range", responseContext)
	}
	protocol, err := stringField(object["protocol"], responseContext+" protocol")
	if err != nil {
		return caseResponse{}, err
	}
	if protocol == "" {
		return caseResponse{}, fmt.Errorf("%s protocol is empty", responseContext)
	}
	headers, err := parseHeaders(object["headers"], corpusRoot, responseContext, tracker)
	if err != nil {
		return caseResponse{}, err
	}
	body, err := resolveBytes(object["body"], corpusRoot, responseContext)
	if err != nil {
		return caseResponse{}, err
	}
	tracker.track(body.fixtureSHA)
	chunkCount, err := parseChunkCount(object["chunks"], len(body.data), responseContext)
	if err != nil {
		return caseResponse{}, err
	}
	return caseResponse{
		status:     int(status),
		protocol:   protocol,
		headers:    headers,
		body:       body.data,
		chunkCount: chunkCount,
	}, nil
}

// parseProcessor parses the policy block and rejects unsupported host settings.
func parseProcessor(raw json.RawMessage, corpusRoot, context string, tracker *fixtureTracker) (string, error) {
	object, err := asObject(raw, context+" processor", []string{
		"sec_lang",
		"request_body_processor",
		"response_body_processor",
		"config",
	}, nil)
	if err != nil {
		return "", err
	}
	processorContext := context + " processor"
	secLang, fixtureSHA, err := resolveText(object["sec_lang"], corpusRoot, processorContext)
	if err != nil {
		return "", err
	}
	tracker.track(fixtureSHA)
	for _, field := range []struct {
		name      string
		supported map[string]struct{}
	}{
		{"request_body_processor", map[string]struct{}{
			"auto": {}, "raw": {}, "urlencoded": {}, "multipart": {}, "json": {}, "xml": {},
		}},
		{"response_body_processor", map[string]struct{}{
			"auto": {}, "raw": {}, "json": {}, "xml": {},
		}},
	} {
		value, err := stringField(object[field.name], processorContext+" "+field.name)
		if err != nil {
			return "", err
		}
		if _, known := field.supported[value]; !known {
			return "", fmt.Errorf("%s field %s has unknown value %s", processorContext, field.name, value)
		}
		if value != "auto" {
			return "", fmt.Errorf(
				"%s field %s=%s is not supported by the Go driver; the common subset uses auto",
				processorContext, field.name, value,
			)
		}
	}
	config, err := asMap(object["config"], processorContext+" config")
	if err != nil {
		return "", err
	}
	for key := range config {
		return "", fmt.Errorf(
			"%s config key %s is not supported by the Go driver; use SecLang directives",
			processorContext, key,
		)
	}
	return secLang, nil
}

// parsePhaseCalls parses the ordered lifecycle and enforces the canonical
// phase-1 to phase-5 sequence.
func parsePhaseCalls(raw json.RawMessage, request caseRequest, response caseResponse, context string) ([]phaseCall, error) {
	items, err := asArray(raw, context+" phase_calls")
	if err != nil {
		return nil, err
	}
	calls := make([]phaseCall, 0, len(items))
	for index, item := range items {
		itemContext := fmt.Sprintf("%s phase call %d", context, index)
		object, err := asObject(item, itemContext, []string{"call", "phase"}, []string{"chunk_index"})
		if err != nil {
			return nil, err
		}
		name, err := stringField(object["call"], itemContext+" call")
		if err != nil {
			return nil, err
		}
		switch name {
		case "process_connection", "process_uri", "process_request_headers",
			"append_request_body", "process_request_body", "process_response_headers",
			"append_response_body", "process_response_body", "process_logging":
		default:
			return nil, fmt.Errorf("%s has unknown call %s", itemContext, name)
		}
		phase, err := uintField(object["phase"], itemContext+" phase")
		if err != nil {
			return nil, err
		}
		if phase < 1 || phase > 5 {
			return nil, fmt.Errorf("%s phase is out of range", itemContext)
		}
		chunkIndex := (*int)(nil)
		if rawIndex, ok := object["chunk_index"]; ok {
			value, err := optionalUintField(rawIndex, itemContext+" chunk_index")
			if err != nil {
				return nil, err
			}
			if value != nil {
				if *value > math.MaxInt {
					return nil, fmt.Errorf("%s chunk_index is out of range", itemContext)
				}
				index := int(*value)
				chunkIndex = &index
			}
		}
		calls = append(calls, phaseCall{call: name, phase: int(phase), chunkIndex: chunkIndex})
	}
	canonical := canonicalCalls(request.chunkCount, response.chunkCount)
	if !sameCalls(calls, canonical) {
		return nil, fmt.Errorf(
			"%s phase_calls do not match the canonical lifecycle; the common subset runs connection, URI, headers, one append per chunk, body, response headers, one append per response chunk, response body and logging",
			context,
		)
	}
	return calls, nil
}

// canonicalCalls builds the only lifecycle sequence this driver accepts.
func canonicalCalls(requestChunks, responseChunks int) []phaseCall {
	calls := []phaseCall{
		{call: "process_connection", phase: 1},
		{call: "process_uri", phase: 1},
		{call: "process_request_headers", phase: 1},
	}
	appendChunk := func(name string, phase, index int) phaseCall {
		chunkIndex := index
		return phaseCall{call: name, phase: phase, chunkIndex: &chunkIndex}
	}
	for index := 0; index < requestChunks; index++ {
		calls = append(calls, appendChunk("append_request_body", 2, index))
	}
	calls = append(calls, phaseCall{call: "process_request_body", phase: 2})
	calls = append(calls, phaseCall{call: "process_response_headers", phase: 3})
	for index := 0; index < responseChunks; index++ {
		calls = append(calls, appendChunk("append_response_body", 4, index))
	}
	calls = append(calls,
		phaseCall{call: "process_response_body", phase: 4},
		phaseCall{call: "process_logging", phase: 5},
	)
	return calls
}

// sameCalls compares lifecycle calls including optional chunk indexes.
func sameCalls(left, right []phaseCall) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].call != right[index].call || left[index].phase != right[index].phase {
			return false
		}
		switch {
		case left[index].chunkIndex == nil && right[index].chunkIndex == nil:
		case left[index].chunkIndex == nil || right[index].chunkIndex == nil:
			return false
		case *left[index].chunkIndex != *right[index].chunkIndex:
			return false
		}
	}
	return true
}

// parseExpected parses the expected outcome and rejects parts the Go driver
// cannot observe.
func parseExpected(raw json.RawMessage, corpusRoot, context string) (expectedOutcome, error) {
	object, err := asObject(raw, context+" expected", []string{
		"matches",
		"interruptions",
		"captures",
		"scores",
		"flags",
		"collections",
		"audit",
	}, nil)
	if err != nil {
		return expectedOutcome{}, err
	}
	expectedContext := context + " expected"
	matches, err := parseExpectedMatches(object["matches"], corpusRoot, expectedContext)
	if err != nil {
		return expectedOutcome{}, err
	}
	interruptions, err := parseExpectedInterruptions(object["interruptions"], corpusRoot, expectedContext)
	if err != nil {
		return expectedOutcome{}, err
	}
	if len(interruptions) > 1 {
		return expectedOutcome{}, fmt.Errorf(
			"%s declares more than one interruption; the engine exposes only one",
			expectedContext,
		)
	}
	captures, err := parseExpectedCaptures(object["captures"], corpusRoot, expectedContext)
	if err != nil {
		return expectedOutcome{}, err
	}
	scores, err := parseScores(object["scores"], expectedContext)
	if err != nil {
		return expectedOutcome{}, err
	}
	flags, err := parseFlags(object["flags"], expectedContext)
	if err != nil {
		return expectedOutcome{}, err
	}
	collections, err := parseExpectedCollections(object["collections"], corpusRoot, expectedContext)
	if err != nil {
		return expectedOutcome{}, err
	}
	audit, err := asObject(object["audit"], expectedContext+" audit", []string{"required", "parts", "entries"}, nil)
	if err != nil {
		return expectedOutcome{}, err
	}
	required, err := boolField(audit["required"], expectedContext+" audit required")
	if err != nil {
		return expectedOutcome{}, err
	}
	if _, err := stringField(audit["parts"], expectedContext+" audit parts"); err != nil {
		return expectedOutcome{}, err
	}
	entries, err := uintField(audit["entries"], expectedContext+" audit entries")
	if err != nil {
		return expectedOutcome{}, err
	}
	if required || entries != 0 {
		return expectedOutcome{}, fmt.Errorf(
			"%s audit required=%t entries=%d is not supported by the Go driver; the common subset uses required=false, entries=0",
			expectedContext, required, entries,
		)
	}
	return expectedOutcome{
		matches:       matches,
		interruptions: interruptions,
		captures:      captures,
		scores:        scores,
		flags:         flags,
		collections:   collections,
	}, nil
}

// parseExpectedMatches parses expected matches.
func parseExpectedMatches(raw json.RawMessage, corpusRoot, context string) ([]expectedMatch, error) {
	items, err := asArray(raw, context+" matches")
	if err != nil {
		return nil, err
	}
	matches := make([]expectedMatch, 0, len(items))
	for index, item := range items {
		itemContext := fmt.Sprintf("%s match %d", context, index)
		object, err := asObject(item, itemContext, []string{"rule_id", "phase", "variable", "key", "value"}, nil)
		if err != nil {
			return nil, err
		}
		ruleID, err := intField(object["rule_id"], itemContext+" rule_id")
		if err != nil {
			return nil, err
		}
		if ruleID < math.MinInt32 || ruleID > math.MaxInt32 {
			return nil, fmt.Errorf("%s rule_id is out of range", itemContext)
		}
		phase, err := uintField(object["phase"], itemContext+" phase")
		if err != nil {
			return nil, err
		}
		if phase < 1 || phase > 5 {
			return nil, fmt.Errorf("%s phase is out of range", itemContext)
		}
		variable, err := stringField(object["variable"], itemContext+" variable")
		if err != nil {
			return nil, err
		}
		key, err := optionalStringField(object["key"], itemContext+" key")
		if err != nil {
			return nil, err
		}
		value, err := resolveBytes(object["value"], corpusRoot, itemContext)
		if err != nil {
			return nil, err
		}
		matches = append(matches, expectedMatch{
			ruleID:   ruleID,
			phase:    int(phase),
			variable: variable,
			key:      key,
			value:    value.data,
		})
	}
	return matches, nil
}

// parseExpectedInterruptions parses expected interruptions.
func parseExpectedInterruptions(raw json.RawMessage, corpusRoot, context string) ([]expectedInterruption, error) {
	items, err := asArray(raw, context+" interruptions")
	if err != nil {
		return nil, err
	}
	interruptions := make([]expectedInterruption, 0, len(items))
	for index, item := range items {
		itemContext := fmt.Sprintf("%s interruption %d", context, index)
		object, err := asObject(item, itemContext, []string{"rule_id", "action", "status", "data"}, nil)
		if err != nil {
			return nil, err
		}
		ruleID, err := intField(object["rule_id"], itemContext+" rule_id")
		if err != nil {
			return nil, err
		}
		if ruleID < math.MinInt32 || ruleID > math.MaxInt32 {
			return nil, fmt.Errorf("%s rule_id is out of range", itemContext)
		}
		action, err := stringField(object["action"], itemContext+" action")
		if err != nil {
			return nil, err
		}
		if action == "" {
			return nil, fmt.Errorf("%s action is empty", itemContext)
		}
		status, err := intField(object["status"], itemContext+" status")
		if err != nil {
			return nil, err
		}
		data, err := resolveBytes(object["data"], corpusRoot, itemContext)
		if err != nil {
			return nil, err
		}
		interruptions = append(interruptions, expectedInterruption{
			ruleID: ruleID,
			action: action,
			status: status,
			data:   data.data,
		})
	}
	return interruptions, nil
}

// parseExpectedCaptures parses expected captures.
func parseExpectedCaptures(raw json.RawMessage, corpusRoot, context string) ([]expectedCapture, error) {
	items, err := asArray(raw, context+" captures")
	if err != nil {
		return nil, err
	}
	captures := make([]expectedCapture, 0, len(items))
	for position, item := range items {
		itemContext := fmt.Sprintf("%s capture %d", context, position)
		object, err := asObject(item, itemContext, []string{"index", "value"}, nil)
		if err != nil {
			return nil, err
		}
		index, err := uintField(object["index"], itemContext+" index")
		if err != nil {
			return nil, err
		}
		if index > maxCaptureIndex {
			return nil, fmt.Errorf(
				"%s index %d is above the maximum capture index %d",
				itemContext, index, maxCaptureIndex,
			)
		}
		value, err := resolveBytes(object["value"], corpusRoot, itemContext)
		if err != nil {
			return nil, err
		}
		captures = append(captures, expectedCapture{index: int(index), value: value.data})
	}
	return captures, nil
}

// parseScores parses the named scores object.
func parseScores(raw json.RawMessage, context string) (map[string]int64, error) {
	object, err := asMap(raw, context+" scores")
	if err != nil {
		return nil, err
	}
	scores := make(map[string]int64, len(object))
	for key, item := range object {
		score, err := intField(item, context+" score "+key)
		if err != nil {
			return nil, err
		}
		scores[key] = score
	}
	return scores, nil
}

// parseFlags parses the named flags object.
func parseFlags(raw json.RawMessage, context string) (map[string]string, error) {
	object, err := asMap(raw, context+" flags")
	if err != nil {
		return nil, err
	}
	flags := make(map[string]string, len(object))
	for key, item := range object {
		flag, err := stringField(item, context+" flag "+key)
		if err != nil {
			return nil, err
		}
		flags[key] = flag
	}
	return flags, nil
}

// parseExpectedCollections parses expected collection values.
func parseExpectedCollections(raw json.RawMessage, corpusRoot, context string) ([]expectedCollection, error) {
	items, err := asArray(raw, context+" collections")
	if err != nil {
		return nil, err
	}
	collections := make([]expectedCollection, 0, len(items))
	for index, item := range items {
		itemContext := fmt.Sprintf("%s collection %d", context, index)
		object, err := asObject(item, itemContext, []string{"variable", "key", "value"}, nil)
		if err != nil {
			return nil, err
		}
		name, err := stringField(object["variable"], itemContext+" variable")
		if err != nil {
			return nil, err
		}
		if name == "" {
			return nil, fmt.Errorf("%s variable is empty", itemContext)
		}
		parsed, err := variables.Parse(strings.ToUpper(name))
		if err != nil {
			return nil, fmt.Errorf("%s: unknown variable %s", itemContext, name)
		}
		key, err := optionalStringField(object["key"], itemContext+" key")
		if err != nil {
			return nil, err
		}
		value, err := resolveBytes(object["value"], corpusRoot, itemContext)
		if err != nil {
			return nil, err
		}
		collections = append(collections, expectedCollection{
			variable: name,
			key:      key,
			value:    value.data,
			parsed:   parsed,
		})
	}
	return collections, nil
}

// parseNormalize validates the declared nondeterminism names.
func parseNormalize(raw json.RawMessage, context string) error {
	items, err := asArray(raw, context+" normalize")
	if err != nil {
		return err
	}
	for index, item := range items {
		name, err := stringField(item, fmt.Sprintf("%s normalize %d", context, index))
		if err != nil {
			return err
		}
		if _, known := normalizations[name]; !known {
			return fmt.Errorf("%s has unknown normalization %s", context, name)
		}
	}
	return nil
}

// checkFixtureSHA compares the case-level fixture hash with the resolved bytes.
func checkFixtureSHA(
	raw json.RawMessage,
	request caseRequest,
	response caseResponse,
	tracker *fixtureTracker,
	context string,
) error {
	declared, err := stringField(raw, context+" fixture_sha256")
	if err != nil {
		return err
	}
	if !isSHA256(declared) {
		return fmt.Errorf("%s fixture_sha256 is malformed", context)
	}
	expected := ""
	if tracker.first != nil {
		expected = *tracker.first
	} else {
		joined := make([]byte, 0, len(request.body)+len(response.body))
		joined = append(joined, request.body...)
		joined = append(joined, response.body...)
		expected = sha256Hex(joined)
	}
	if declared != expected {
		return fmt.Errorf("%s fixture_sha256 is %s, not %s", context, declared, expected)
	}
	return nil
}

// resolveBytes decodes inline base64 or reads a validated fixture range.
func resolveBytes(raw json.RawMessage, corpusRoot, context string) (resolvedBytes, error) {
	object, err := asObject(raw, context, nil, []string{"base64", "fixture", "sha256", "offset", "length"})
	if err != nil {
		return resolvedBytes{}, err
	}
	_, inline := object["base64"]
	_, fixture := object["fixture"]
	switch {
	case inline && !fixture:
		for key := range object {
			if key != "base64" {
				return resolvedBytes{}, fmt.Errorf("%s has unknown field %s", context, key)
			}
		}
		encoded, err := stringField(object["base64"], context+" base64")
		if err != nil {
			return resolvedBytes{}, err
		}
		data, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return resolvedBytes{}, fmt.Errorf("%s has invalid base64: %w", context, err)
		}
		return resolvedBytes{data: data}, nil
	case !inline && fixture:
		for key := range object {
			switch key {
			case "fixture", "sha256", "offset", "length":
			default:
				return resolvedBytes{}, fmt.Errorf("%s has unknown field %s", context, key)
			}
		}
		return resolveFixture(object, corpusRoot, context)
	default:
		return resolvedBytes{}, fmt.Errorf("%s must have exactly one of base64 or fixture", context)
	}
}

// resolveFixture reads and verifies one fixture range.
func resolveFixture(object jsonObject, corpusRoot, context string) (resolvedBytes, error) {
	fixture, err := stringField(object["fixture"], context+" fixture")
	if err != nil {
		return resolvedBytes{}, err
	}
	relative, err := relativePath(fixture, context+" fixture")
	if err != nil {
		return resolvedBytes{}, err
	}
	path := filepath.Join(corpusRoot, filepath.FromSlash(relative))
	data, err := readFileBounded(path)
	if err != nil {
		return resolvedBytes{}, fmt.Errorf("%s cannot read fixture %s: %w", context, path, err)
	}
	declared, err := stringField(object["sha256"], context+" sha256")
	if err != nil {
		return resolvedBytes{}, err
	}
	if !isSHA256(declared) {
		return resolvedBytes{}, fmt.Errorf("%s fixture hash is malformed", context)
	}
	actual := sha256Hex(data)
	if actual != declared {
		return resolvedBytes{}, fmt.Errorf("%s fixture %s has SHA-256 %s, not %s", context, path, actual, declared)
	}
	offset := uint64(0)
	if rawOffset, ok := object["offset"]; ok {
		value, err := optionalUintField(rawOffset, context+" offset")
		if err != nil {
			return resolvedBytes{}, err
		}
		if value != nil {
			offset = *value
		}
	}
	if offset > uint64(len(data)) {
		return resolvedBytes{}, fmt.Errorf("%s fixture offset %d is past the end of %s", context, offset, path)
	}
	end := uint64(len(data))
	if rawLength, ok := object["length"]; ok {
		length, err := optionalUintField(rawLength, context+" length")
		if err != nil {
			return resolvedBytes{}, err
		}
		if length != nil {
			if *length > math.MaxUint64-offset {
				return resolvedBytes{}, fmt.Errorf("%s fixture range overflows", context)
			}
			end = offset + *length
		}
	}
	if end > uint64(len(data)) {
		return resolvedBytes{}, fmt.Errorf(
			"%s fixture range %d..%d is past the end of %s",
			context, offset, end, path,
		)
	}
	bytes := make([]byte, end-offset)
	copy(bytes, data[offset:end])
	return resolvedBytes{data: bytes, fixtureSHA: &actual}, nil
}

// resolveText resolves inline UTF-8 text or a validated fixture range.
func resolveText(raw json.RawMessage, corpusRoot, context string) (string, *string, error) {
	object, err := asObject(raw, context, nil, []string{"utf8", "fixture", "sha256", "offset", "length"})
	if err != nil {
		return "", nil, err
	}
	if _, inline := object["utf8"]; inline {
		for key := range object {
			if key != "utf8" {
				return "", nil, fmt.Errorf("%s has unknown field %s", context, key)
			}
		}
		text, err := stringField(object["utf8"], context+" utf8")
		if err != nil {
			return "", nil, err
		}
		return text, nil, nil
	}
	resolved, err := resolveFixture(object, corpusRoot, context)
	if err != nil {
		return "", nil, err
	}
	if !utf8.Valid(resolved.data) {
		return "", nil, fmt.Errorf("%s fixture is not valid UTF-8", context)
	}
	return string(resolved.data), resolved.fixtureSHA, nil
}
