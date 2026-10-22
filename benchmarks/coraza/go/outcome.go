// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package bench

// Language-neutral outcome documents shared with the Rust driver. Values that
// are bytes are standard base64. Rule matches keep evaluation order, captures
// keep index order and collections keep the order the case declares. The
// per-match phase is absent because the Go public API does not expose it.

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// OutcomeMatch is one observed rule match. Key is null when the variable is
// not keyed and Value is standard base64.
type OutcomeMatch struct {
	RuleID   int64   `json:"rule_id"`
	Variable string  `json:"variable"`
	Key      *string `json:"key"`
	Value    string  `json:"value"`
}

// OutcomeInterruption is the effective interruption, if any.
type OutcomeInterruption struct {
	RuleID int64  `json:"rule_id"`
	Action string `json:"action"`
	Status int64  `json:"status"`
	Data   string `json:"data"`
}

// OutcomeCapture is one TX capture in index order.
type OutcomeCapture struct {
	Index int    `json:"index"`
	Value string `json:"value"`
}

// OutcomeCollection is one observed collection value. Value is null when the
// collection or key is absent.
type OutcomeCollection struct {
	Variable string  `json:"variable"`
	Key      *string `json:"key"`
	Value    *string `json:"value"`
}

// Outcome is the observable result of one case in the shared document shape.
type Outcome struct {
	CaseID       string               `json:"case_id"`
	Interruption *OutcomeInterruption `json:"interruption"`
	Matches      []OutcomeMatch       `json:"matches"`
	Captures     []OutcomeCapture     `json:"captures"`
	Scores       map[string]int64     `json:"scores"`
	Flags        map[string]string    `json:"flags"`
	Collections  []OutcomeCollection  `json:"collections"`
}

// observableFlagVariables maps the engine flag names a case may declare to the
// Go collection that holds them. RES_BODY_ERROR and RES_BODY_PROCESSOR_ERROR
// are absent: v3.8.1 does not expose them through the plugin transaction
// interface or through Transaction.Collection.
var observableFlagVariables = map[string]variables.RuleVariable{
	"REQBODY_ERROR":           variables.ReqbodyError,
	"REQBODY_PROCESSOR_ERROR": variables.ReqbodyProcessorError,
	"INBOUND_DATA_ERROR":      variables.InboundDataError,
	"OUTBOUND_DATA_ERROR":     variables.OutboundDataError,
	"MULTIPART_STRICT_ERROR":  variables.MultipartStrictError,
	"ARGUMENTS_LIMIT_REACHED": variables.ArgumentsLimitReached,
}

// variableAccessor is the exported plugin accessor implemented by the concrete
// transaction returned by WAF.NewTransaction.
type variableAccessor interface {
	Variables() plugintypes.TransactionVariables
}

// collectionAccessor is the exported collection accessor implemented by the
// concrete transaction returned by WAF.NewTransaction.
type collectionAccessor interface {
	Collection(variables.RuleVariable) collection.Collection
}

// RunCase drives one case through the same lifecycle Engine.Run uses and
// observes the result before the transaction is closed.
func RunCase(prepared *PreparedCase) (Outcome, error) {
	tx := prepared.engine.waf.NewTransaction()
	defer func() {
		_ = tx.Close()
	}()
	driveErr := drive(tx, prepared.request)
	tx.ProcessLogging()
	if driveErr != nil {
		return Outcome{}, fmt.Errorf("case %s: %w", prepared.ID, driveErr)
	}
	return observe(tx, prepared.ID, prepared.expected)
}

// observe reads the widest observable subset of the public Go API.
func observe(tx types.Transaction, caseID string, expected expectedOutcome) (Outcome, error) {
	outcome := Outcome{
		CaseID:      caseID,
		Matches:     []OutcomeMatch{},
		Captures:    []OutcomeCapture{},
		Scores:      make(map[string]int64, len(expected.scores)),
		Flags:       make(map[string]string, len(expected.flags)),
		Collections: []OutcomeCollection{},
	}
	if interruption := tx.Interruption(); interruption != nil {
		outcome.Interruption = &OutcomeInterruption{
			RuleID: int64(interruption.RuleID),
			Action: interruption.Action,
			Status: int64(interruption.Status),
			Data:   base64.StdEncoding.EncodeToString([]byte(interruption.Data)),
		}
	}
	for _, matched := range tx.MatchedRules() {
		for _, data := range matched.MatchedDatas() {
			match := OutcomeMatch{
				RuleID:   int64(matched.Rule().ID()),
				Variable: data.Variable().Name(),
				Value:    base64.StdEncoding.EncodeToString([]byte(data.Value())),
			}
			if key := data.Key(); key != "" {
				match.Key = &key
			}
			outcome.Matches = append(outcome.Matches, match)
		}
	}

	accessor, ok := tx.(variableAccessor)
	if !ok {
		return Outcome{}, fmt.Errorf("case %s: the transaction does not expose the plugin Variables accessor", caseID)
	}
	collections, ok := tx.(collectionAccessor)
	if !ok {
		return Outcome{}, fmt.Errorf("case %s: the transaction does not expose the Collection accessor", caseID)
	}

	txVariables := accessor.Variables().TX()
	for index := 0; index <= maxCaptureIndex; index++ {
		values := txVariables.Get(strconv.Itoa(index))
		if len(values) == 0 || values[0] == "" {
			// The Go transaction seeds TX 0..10 with empty strings; an empty
			// slot is unset, matching the Rust driver's absent-key behavior.
			continue
		}
		outcome.Captures = append(outcome.Captures, OutcomeCapture{
			Index: index,
			Value: base64.StdEncoding.EncodeToString([]byte(values[0])),
		})
	}
	for name := range expected.scores {
		values := txVariables.Get(name)
		score := int64(0)
		switch {
		case len(values) == 0:
		case values[0] == "" && seededTXKey(name):
		case values[0] == "":
			return Outcome{}, fmt.Errorf("case %s TX:%s is not an integer", caseID, name)
		default:
			parsed, err := strconv.ParseInt(values[0], 10, 64)
			if err != nil {
				return Outcome{}, fmt.Errorf("case %s TX:%s is not an integer: %w", caseID, name, err)
			}
			score = parsed
		}
		outcome.Scores[name] = score
	}
	for name := range expected.flags {
		variable, known := observableFlagVariables[name]
		if !known {
			// CheckExpected reports the flag as unobservable.
			continue
		}
		single, ok := collections.Collection(variable).(collection.Single)
		if !ok {
			continue
		}
		outcome.Flags[name] = single.Get()
	}
	for _, item := range expected.collections {
		observed := OutcomeCollection{Variable: item.variable, Key: item.key}
		switch {
		case item.key == nil:
			if single, ok := collections.Collection(item.parsed).(collection.Single); ok {
				value := base64.StdEncoding.EncodeToString([]byte(single.Get()))
				observed.Value = &value
			}
		default:
			if keyed, ok := collections.Collection(item.parsed).(collection.Keyed); ok {
				if values := keyed.Get(*item.key); len(values) > 0 {
					value := base64.StdEncoding.EncodeToString([]byte(values[0]))
					observed.Value = &value
				}
			}
		}
		outcome.Collections = append(outcome.Collections, observed)
	}
	return outcome, nil
}

// seededTXKey reports whether the Go transaction pre-seeds this TX key with an
// empty string (capture slots 0 through 10).
func seededTXKey(name string) bool {
	value, err := strconv.Atoi(name)
	return err == nil && value >= 0 && value <= 10
}

// CheckExpected compares an observed outcome with the case's expected block.
// The per-match phase is not compared: the Go public API does not expose it.
func CheckExpected(prepared *PreparedCase, outcome Outcome) error {
	expected := prepared.expected
	if len(expected.matches) != len(outcome.Matches) {
		return fmt.Errorf(
			"case %s matched %d rule occurrences, expected %d",
			prepared.ID, len(outcome.Matches), len(expected.matches),
		)
	}
	for index, want := range expected.matches {
		got := outcome.Matches[index]
		if want.ruleID != got.RuleID || want.variable != got.Variable ||
			!sameOptionalString(want.key, got.Key) || base64.StdEncoding.EncodeToString(want.value) != got.Value {
			return fmt.Errorf(
				"case %s match %d is rule %d %s:%s, expected rule %d %s:%s",
				prepared.ID, index, got.RuleID, got.Variable, formatOptionalString(got.Key),
				want.ruleID, want.variable, formatOptionalString(want.key),
			)
		}
	}
	if err := checkInterruption(prepared.ID, expected.interruptions, outcome.Interruption); err != nil {
		return err
	}
	if len(expected.captures) != len(outcome.Captures) {
		return fmt.Errorf(
			"case %s observed %d captures, expected %d",
			prepared.ID, len(outcome.Captures), len(expected.captures),
		)
	}
	for index, want := range expected.captures {
		got := outcome.Captures[index]
		if want.index != got.Index || base64.StdEncoding.EncodeToString(want.value) != got.Value {
			return fmt.Errorf(
				"case %s capture %d is TX:%d, expected TX:%d",
				prepared.ID, index, got.Index, want.index,
			)
		}
	}
	for _, name := range sortedKeys(expected.scores) {
		want := expected.scores[name]
		got := outcome.Scores[name]
		if want != got {
			return fmt.Errorf("case %s score %s is %d, expected %d", prepared.ID, name, got, want)
		}
	}
	for _, name := range sortedKeys(expected.flags) {
		want := expected.flags[name]
		got, ok := outcome.Flags[name]
		if !ok {
			return fmt.Errorf("case %s flag %s is not observable, expected %s", prepared.ID, name, want)
		}
		if want != got {
			return fmt.Errorf("case %s flag %s is %s, expected %s", prepared.ID, name, got, want)
		}
	}
	if len(expected.collections) != len(outcome.Collections) {
		return fmt.Errorf(
			"case %s observed %d collection values, expected %d",
			prepared.ID, len(outcome.Collections), len(expected.collections),
		)
	}
	for index, want := range expected.collections {
		got := outcome.Collections[index]
		wantValue := base64.StdEncoding.EncodeToString(want.value)
		if want.variable != got.Variable || !sameOptionalString(want.key, got.Key) ||
			got.Value == nil || *got.Value != wantValue {
			return fmt.Errorf(
				"case %s collection %d %s:%s is %s, expected %s",
				prepared.ID, index, got.Variable, formatOptionalString(got.Key),
				formatOptionalString(got.Value), wantValue,
			)
		}
	}
	return nil
}

// checkInterruption compares the effective interruption.
func checkInterruption(caseID string, expected []expectedInterruption, observed *OutcomeInterruption) error {
	switch {
	case len(expected) == 0 && observed == nil:
		return nil
	case len(expected) == 0 && observed != nil:
		return fmt.Errorf("case %s was interrupted by rule %d but the case expected none", caseID, observed.RuleID)
	case observed == nil:
		return fmt.Errorf("case %s expected interruption by rule %d but none occurred", caseID, expected[0].ruleID)
	default:
		want := expected[0]
		if want.ruleID != observed.RuleID || want.action != observed.Action ||
			want.status != observed.Status || base64.StdEncoding.EncodeToString(want.data) != observed.Data {
			return fmt.Errorf(
				"case %s interrupted by rule %d action %s status %d, expected rule %d action %s status %d",
				caseID, observed.RuleID, observed.Action, observed.Status, want.ruleID, want.action, want.status,
			)
		}
		return nil
	}
}

// sameOptionalString compares two optional strings.
func sameOptionalString(left, right *string) bool {
	switch {
	case left == nil && right == nil:
		return true
	case left == nil || right == nil:
		return false
	default:
		return *left == *right
	}
}

// formatOptionalString renders an optional string for an error message.
func formatOptionalString(value *string) string {
	if value == nil {
		return "<none>"
	}
	return *value
}

// sortedKeys returns map keys in deterministic order for error messages.
func sortedKeys[V any](items map[string]V) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// WriteOutcomes writes one JSON object per line.
func WriteOutcomes(writer io.Writer, outcomes []Outcome) error {
	buffered := bufio.NewWriter(writer)
	encoder := json.NewEncoder(buffered)
	encoder.SetEscapeHTML(false)
	for _, outcome := range outcomes {
		if err := encoder.Encode(outcome); err != nil {
			return fmt.Errorf("encode outcome: %w", err)
		}
	}
	if err := buffered.Flush(); err != nil {
		return fmt.Errorf("write outcomes: %w", err)
	}
	return nil
}

// WriteOutcomesFile writes outcome documents to a new file.
func WriteOutcomesFile(path string, outcomes []Outcome) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create outcome file %s: %w", path, err)
	}
	writeErr := WriteOutcomes(file, outcomes)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return fmt.Errorf("close outcome file %s: %w", path, closeErr)
	}
	return nil
}

// ReadOutcomesFile reads and parses a bounded NDJSON outcome document.
func ReadOutcomesFile(path string) ([]Outcome, error) {
	data, err := readFileBounded(path)
	if err != nil {
		return nil, fmt.Errorf("read outcome file %s: %w", path, err)
	}
	outcomes, err := ParseOutcomes(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return outcomes, nil
}

// ParseOutcomes reads and validates an NDJSON outcome document. Duplicate case
// IDs are rejected.
func ParseOutcomes(reader io.Reader) ([]Outcome, error) {
	decoder := json.NewDecoder(reader)
	outcomes := []Outcome{}
	seen := map[string]struct{}{}
	for {
		var raw json.RawMessage
		err := decoder.Decode(&raw)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("outcome document is not valid NDJSON: %w", err)
		}
		outcome, err := parseOutcome(raw)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[outcome.CaseID]; duplicate {
			return nil, fmt.Errorf("outcome document repeats case %s", outcome.CaseID)
		}
		seen[outcome.CaseID] = struct{}{}
		outcomes = append(outcomes, outcome)
	}
	if len(outcomes) == 0 {
		return nil, fmt.Errorf("outcome document is empty")
	}
	return outcomes, nil
}

// parseOutcome validates one outcome object.
func parseOutcome(raw json.RawMessage) (Outcome, error) {
	object, err := asObject(raw, "outcome", []string{
		"case_id",
		"interruption",
		"matches",
		"captures",
		"scores",
		"flags",
		"collections",
	}, nil)
	if err != nil {
		return Outcome{}, err
	}
	caseID, err := stringField(object["case_id"], "outcome case_id")
	if err != nil {
		return Outcome{}, err
	}
	if caseID == "" {
		return Outcome{}, fmt.Errorf("outcome case_id is empty")
	}
	context := "outcome " + caseID
	outcome := Outcome{
		CaseID:      caseID,
		Matches:     []OutcomeMatch{},
		Captures:    []OutcomeCapture{},
		Scores:      map[string]int64{},
		Flags:       map[string]string{},
		Collections: []OutcomeCollection{},
	}
	if !isNull(object["interruption"]) {
		item, err := asObject(object["interruption"], context+" interruption", []string{
			"rule_id", "action", "status", "data",
		}, nil)
		if err != nil {
			return Outcome{}, err
		}
		interruption := &OutcomeInterruption{}
		if interruption.RuleID, err = intField(item["rule_id"], context+" interruption rule_id"); err != nil {
			return Outcome{}, err
		}
		if interruption.Action, err = stringField(item["action"], context+" interruption action"); err != nil {
			return Outcome{}, err
		}
		if interruption.Action == "" {
			return Outcome{}, fmt.Errorf("%s interruption action is empty", context)
		}
		if interruption.Status, err = intField(item["status"], context+" interruption status"); err != nil {
			return Outcome{}, err
		}
		interruption.Data, err = base64Field(item["data"], context+" interruption data")
		if err != nil {
			return Outcome{}, err
		}
		outcome.Interruption = interruption
	}
	matches, err := asArray(object["matches"], context+" matches")
	if err != nil {
		return Outcome{}, err
	}
	for index, item := range matches {
		itemContext := fmt.Sprintf("%s match %d", context, index)
		match, err := asObject(item, itemContext, []string{"rule_id", "variable", "key", "value"}, nil)
		if err != nil {
			return Outcome{}, err
		}
		parsed := OutcomeMatch{}
		if parsed.RuleID, err = intField(match["rule_id"], itemContext+" rule_id"); err != nil {
			return Outcome{}, err
		}
		if parsed.Variable, err = stringField(match["variable"], itemContext+" variable"); err != nil {
			return Outcome{}, err
		}
		if parsed.Key, err = optionalStringField(match["key"], itemContext+" key"); err != nil {
			return Outcome{}, err
		}
		if parsed.Value, err = base64Field(match["value"], itemContext+" value"); err != nil {
			return Outcome{}, err
		}
		outcome.Matches = append(outcome.Matches, parsed)
	}
	captures, err := asArray(object["captures"], context+" captures")
	if err != nil {
		return Outcome{}, err
	}
	for index, item := range captures {
		itemContext := fmt.Sprintf("%s capture %d", context, index)
		capture, err := asObject(item, itemContext, []string{"index", "value"}, nil)
		if err != nil {
			return Outcome{}, err
		}
		position, err := uintField(capture["index"], itemContext+" index")
		if err != nil {
			return Outcome{}, err
		}
		if position > maxCaptureIndex {
			return Outcome{}, fmt.Errorf("%s index is out of range", itemContext)
		}
		value, err := base64Field(capture["value"], itemContext+" value")
		if err != nil {
			return Outcome{}, err
		}
		outcome.Captures = append(outcome.Captures, OutcomeCapture{Index: int(position), Value: value})
	}
	scores, err := asMap(object["scores"], context+" scores")
	if err != nil {
		return Outcome{}, err
	}
	for name, item := range scores {
		score, err := intField(item, context+" score "+name)
		if err != nil {
			return Outcome{}, err
		}
		outcome.Scores[name] = score
	}
	flags, err := asMap(object["flags"], context+" flags")
	if err != nil {
		return Outcome{}, err
	}
	for name, item := range flags {
		flag, err := stringField(item, context+" flag "+name)
		if err != nil {
			return Outcome{}, err
		}
		outcome.Flags[name] = flag
	}
	collections, err := asArray(object["collections"], context+" collections")
	if err != nil {
		return Outcome{}, err
	}
	for index, item := range collections {
		itemContext := fmt.Sprintf("%s collection %d", context, index)
		entry, err := asObject(item, itemContext, []string{"variable", "key", "value"}, nil)
		if err != nil {
			return Outcome{}, err
		}
		name, err := stringField(entry["variable"], itemContext+" variable")
		if err != nil {
			return Outcome{}, err
		}
		if name == "" {
			return Outcome{}, fmt.Errorf("%s variable is empty", itemContext)
		}
		key, err := optionalStringField(entry["key"], itemContext+" key")
		if err != nil {
			return Outcome{}, err
		}
		value, err := optionalBase64Field(entry["value"], itemContext+" value")
		if err != nil {
			return Outcome{}, err
		}
		outcome.Collections = append(outcome.Collections, OutcomeCollection{
			Variable: name,
			Key:      key,
			Value:    value,
		})
	}
	return outcome, nil
}

// base64Field decodes and re-encodes a required base64 string.
func base64Field(raw json.RawMessage, context string) (string, error) {
	encoded, err := stringField(raw, context)
	if err != nil {
		return "", err
	}
	if _, err := base64.StdEncoding.DecodeString(encoded); err != nil {
		return "", fmt.Errorf("%s is not valid base64: %w", context, err)
	}
	return encoded, nil
}

// optionalBase64Field decodes a base64 string that may be null.
func optionalBase64Field(raw json.RawMessage, context string) (*string, error) {
	if isNull(raw) {
		return nil, nil
	}
	encoded, err := base64Field(raw, context)
	if err != nil {
		return nil, err
	}
	return &encoded, nil
}

// CompareOutcomes compares the Rust and Go documents per case and field. It
// returns one message per divergence; an empty result means parity. Arrays are
// compared in order because every emitted array has a defined order: matches
// are in evaluation order, captures in index order and collections in case
// declaration order. JSON objects are compared by key. No collection is
// compared as a multiset, because the public APIs expose no unordered array.
func CompareOutcomes(rust, goOutcomes []Outcome) []string {
	var divergences []string
	goByID := make(map[string]Outcome, len(goOutcomes))
	for _, outcome := range goOutcomes {
		goByID[outcome.CaseID] = outcome
	}
	rustIDs := make(map[string]struct{}, len(rust))
	for _, outcome := range rust {
		rustIDs[outcome.CaseID] = struct{}{}
		if _, ok := goByID[outcome.CaseID]; !ok {
			divergences = append(divergences, fmt.Sprintf("case %s: missing from the Go document", outcome.CaseID))
		}
	}
	for _, outcome := range goOutcomes {
		if _, ok := rustIDs[outcome.CaseID]; !ok {
			divergences = append(divergences, fmt.Sprintf("case %s: missing from the Rust document", outcome.CaseID))
		}
	}
	for _, want := range rust {
		got, ok := goByID[want.CaseID]
		if !ok {
			continue
		}
		divergences = append(divergences, compareOutcome(want, got)...)
	}
	return divergences
}

// compareOutcome compares one case's fields.
func compareOutcome(rust, goOutcome Outcome) []string {
	caseID := rust.CaseID
	var divergences []string
	add := func(field, rustValue, goValue string) {
		divergences = append(divergences, fmt.Sprintf(
			"case %s: %s: rust %s, go %s", caseID, field, rustValue, goValue,
		))
	}
	switch {
	case rust.Interruption == nil && goOutcome.Interruption == nil:
	case rust.Interruption == nil:
		add("interruption", "null", "present")
	case goOutcome.Interruption == nil:
		add("interruption", "present", "null")
	default:
		want, got := rust.Interruption, goOutcome.Interruption
		if want.RuleID != got.RuleID {
			add("interruption.rule_id", strconv.FormatInt(want.RuleID, 10), strconv.FormatInt(got.RuleID, 10))
		}
		if want.Action != got.Action {
			add("interruption.action", strconv.Quote(want.Action), strconv.Quote(got.Action))
		}
		if want.Status != got.Status {
			add("interruption.status", strconv.FormatInt(want.Status, 10), strconv.FormatInt(got.Status, 10))
		}
		if want.Data != got.Data {
			add("interruption.data", strconv.Quote(want.Data), strconv.Quote(got.Data))
		}
	}
	if len(rust.Matches) != len(goOutcome.Matches) {
		add("matches length", strconv.Itoa(len(rust.Matches)), strconv.Itoa(len(goOutcome.Matches)))
	} else {
		for index := range rust.Matches {
			want, got := rust.Matches[index], goOutcome.Matches[index]
			prefix := fmt.Sprintf("matches[%d]", index)
			if want.RuleID != got.RuleID {
				add(prefix+".rule_id", strconv.FormatInt(want.RuleID, 10), strconv.FormatInt(got.RuleID, 10))
			}
			if want.Variable != got.Variable {
				add(prefix+".variable", strconv.Quote(want.Variable), strconv.Quote(got.Variable))
			}
			if !sameOptionalString(want.Key, got.Key) {
				add(prefix+".key", formatOptionalQuoted(want.Key), formatOptionalQuoted(got.Key))
			}
			if want.Value != got.Value {
				add(prefix+".value", strconv.Quote(want.Value), strconv.Quote(got.Value))
			}
		}
	}
	if len(rust.Captures) != len(goOutcome.Captures) {
		add("captures length", strconv.Itoa(len(rust.Captures)), strconv.Itoa(len(goOutcome.Captures)))
	} else {
		for index := range rust.Captures {
			want, got := rust.Captures[index], goOutcome.Captures[index]
			prefix := fmt.Sprintf("captures[%d]", index)
			if want.Index != got.Index {
				add(prefix+".index", strconv.Itoa(want.Index), strconv.Itoa(got.Index))
			}
			if want.Value != got.Value {
				add(prefix+".value", strconv.Quote(want.Value), strconv.Quote(got.Value))
			}
		}
	}
	for _, name := range unionKeys(rust.Scores, goOutcome.Scores) {
		want, wantOK := rust.Scores[name]
		got, gotOK := goOutcome.Scores[name]
		switch {
		case !wantOK:
			add("scores."+name, "missing", strconv.FormatInt(got, 10))
		case !gotOK:
			add("scores."+name, strconv.FormatInt(want, 10), "missing")
		case want != got:
			add("scores."+name, strconv.FormatInt(want, 10), strconv.FormatInt(got, 10))
		}
	}
	for _, name := range unionKeys(rust.Flags, goOutcome.Flags) {
		want, wantOK := rust.Flags[name]
		got, gotOK := goOutcome.Flags[name]
		switch {
		case !wantOK:
			add("flags."+name, "missing", strconv.Quote(got))
		case !gotOK:
			add("flags."+name, strconv.Quote(want), "missing")
		case want != got:
			add("flags."+name, strconv.Quote(want), strconv.Quote(got))
		}
	}
	if len(rust.Collections) != len(goOutcome.Collections) {
		add("collections length", strconv.Itoa(len(rust.Collections)), strconv.Itoa(len(goOutcome.Collections)))
	} else {
		for index := range rust.Collections {
			want, got := rust.Collections[index], goOutcome.Collections[index]
			prefix := fmt.Sprintf("collections[%d]", index)
			if want.Variable != got.Variable {
				add(prefix+".variable", strconv.Quote(want.Variable), strconv.Quote(got.Variable))
			}
			if !sameOptionalString(want.Key, got.Key) {
				add(prefix+".key", formatOptionalQuoted(want.Key), formatOptionalQuoted(got.Key))
			}
			if !sameOptionalString(want.Value, got.Value) {
				add(prefix+".value", formatOptionalQuoted(want.Value), formatOptionalQuoted(got.Value))
			}
		}
	}
	return divergences
}

// formatOptionalQuoted renders an optional string for a divergence message.
func formatOptionalQuoted(value *string) string {
	if value == nil {
		return "null"
	}
	return strconv.Quote(*value)
}

// unionKeys returns the sorted union of two map keys.
func unionKeys[V any](left, right map[string]V) []string {
	seen := make(map[string]struct{}, len(left)+len(right))
	for key := range left {
		seen[key] = struct{}{}
	}
	for key := range right {
		seen[key] = struct{}{}
	}
	return sortedKeys(seen)
}
