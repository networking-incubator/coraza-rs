package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	libinjection "github.com/corazawaf/libinjection-go"
)

type inputCase struct {
	detector string
	size     int
	name     string
	value    string
}

type caseResult struct {
	Size        int    `json:"size"`
	Case        string `json:"case"`
	Detected    bool   `json:"detected"`
	Fingerprint string `json:"fingerprint"`
	P50         int64  `json:"p50_ns"`
	P90         int64  `json:"p90_ns"`
	P99         int64  `json:"p99_ns"`
}

type output struct {
	Detector string       `json:"detector"`
	Samples  int          `json:"samples"`
	Warmup   int          `json:"warmup"`
	Cases    []caseResult `json:"cases"`
}

func readCases(path, detector string) ([]inputCase, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cases []inputCase
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		columns := strings.Split(scanner.Text(), "\t")
		if len(columns) != 4 {
			return nil, fmt.Errorf("case line must have four columns")
		}
		if columns[0] != detector {
			continue
		}
		var size int
		if _, err := fmt.Sscan(columns[1], &size); err != nil {
			return nil, fmt.Errorf("invalid input size: %w", err)
		}
		bytes, err := hex.DecodeString(columns[3])
		if err != nil {
			return nil, fmt.Errorf("invalid case hex: %w", err)
		}
		if len(bytes) != size {
			return nil, fmt.Errorf("%s case length was %d, expected %d", columns[2], len(bytes), size)
		}
		cases = append(cases, inputCase{detector: detector, size: size, name: columns[2], value: string(bytes)})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(cases) == 0 {
		return nil, fmt.Errorf("no input rows for detector %s", detector)
	}
	return cases, nil
}

func quantile(sorted []int64, percent int) int64 {
	rank := (len(sorted)*percent+99)/100 - 1
	return sorted[rank]
}

func main() {
	detector := flag.String("detector", "", "sqli or xss")
	casesPath := flag.String("cases", "", "shared TSV workload file")
	sampleCount := flag.Int("samples", 20000, "individual detector calls to time per case")
	warmupCount := flag.Int("warmup", 2000, "untimed calls per case")
	rawPath := flag.String("raw", "", "raw per-call timing TSV path")
	flag.Parse()
	if (*detector != "sqli" && *detector != "xss") || *casesPath == "" || *rawPath == "" || *sampleCount < 1 || *warmupCount < 0 {
		fmt.Fprintln(os.Stderr, "usage: go-perf -detector <sqli|xss> -cases workloads.tsv -samples N -warmup N -raw samples.tsv")
		os.Exit(2)
	}
	cases, err := readCases(*casesPath, *detector)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read cases:", err)
		os.Exit(2)
	}
	result := output{Detector: *detector, Samples: *sampleCount, Warmup: *warmupCount, Cases: make([]caseResult, 0, len(cases))}
	rawRows := make([][]int64, 0, len(cases))
	for _, testCase := range cases {
		var detected bool
		var fingerprint string
		if *detector == "sqli" {
			for range *warmupCount {
				detected, fingerprint = libinjection.IsSQLi(testCase.value)
			}
			samples := make([]int64, *sampleCount)
			for index := range samples {
				start := time.Now()
				detected, fingerprint = libinjection.IsSQLi(testCase.value)
				samples[index] = time.Since(start).Nanoseconds()
			}
			sorted := append([]int64(nil), samples...)
			sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
			result.Cases = append(result.Cases, caseResult{
				Size: testCase.size, Case: testCase.name, Detected: detected,
				Fingerprint: hex.EncodeToString([]byte(fingerprint)),
				P50:         quantile(sorted, 50), P90: quantile(sorted, 90), P99: quantile(sorted, 99),
			})
			rawRows = append(rawRows, samples)
		} else {
			for range *warmupCount {
				detected = libinjection.IsXSS(testCase.value)
			}
			samples := make([]int64, *sampleCount)
			for index := range samples {
				start := time.Now()
				detected = libinjection.IsXSS(testCase.value)
				samples[index] = time.Since(start).Nanoseconds()
			}
			sorted := append([]int64(nil), samples...)
			sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
			result.Cases = append(result.Cases, caseResult{
				Size: testCase.size, Case: testCase.name, Detected: detected,
				P50: quantile(sorted, 50), P90: quantile(sorted, 90), P99: quantile(sorted, 99),
			})
			rawRows = append(rawRows, samples)
		}
	}
	raw, err := os.Create(*rawPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create raw samples:", err)
		os.Exit(2)
	}
	writer := bufio.NewWriter(raw)
	fmt.Fprintln(writer, "detector\tsize\tcase\titeration\tnanos")
	for caseIndex, testCase := range cases {
		for iteration, nanos := range rawRows[caseIndex] {
			fmt.Fprintf(writer, "%s\t%d\t%s\t%d\t%d\n", *detector, testCase.size, testCase.name, iteration, nanos)
		}
	}
	if err := writer.Flush(); err != nil {
		fmt.Fprintln(os.Stderr, "write raw samples:", err)
		os.Exit(2)
	}
	if err := raw.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "close raw samples:", err)
		os.Exit(2)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "write result:", err)
		os.Exit(2)
	}
}
