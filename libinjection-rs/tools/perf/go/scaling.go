package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	libinjection "github.com/corazawaf/libinjection-go"
)

type scaleInput struct {
	detector string
	api      string
	name     string
	size     int
	path     string
	data     string
}

type scaleOutput struct {
	Cases []map[string]any `json:"cases"`
}

type measured struct {
	samples     []int64
	detected    bool
	fingerprint string
}

func loadScaleInputs(manifest string) ([]scaleInput, error) {
	manifestPath, err := filepath.Abs(manifest)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(manifest)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var inputs []scaleInput
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		columns := strings.Split(scanner.Text(), "\t")
		if len(columns) != 6 {
			return nil, fmt.Errorf("scale manifest row must have six columns")
		}
		var size int
		if _, err := fmt.Sscan(columns[3], &size); err != nil {
			return nil, fmt.Errorf("invalid size: %w", err)
		}
		if columns[0] == "rust" {
			continue
		}
		input := scaleInput{detector: columns[0], api: columns[1], name: columns[2], size: size, path: columns[4]}
		if !filepath.IsAbs(input.path) {
			input.path = filepath.Join(filepath.Dir(manifestPath), input.path)
		}
		bytes, err := os.ReadFile(input.path)
		if err != nil {
			return nil, err
		}
		if len(bytes) != size {
			return nil, fmt.Errorf("%s was %d bytes, manifest says %d", input.path, len(bytes), size)
		}
		input.data = string(bytes)
		inputs = append(inputs, input)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return inputs, nil
}

func quantile(sorted []int64, percent int) int64 {
	rank := (len(sorted)*percent+99)/100 - 1
	return sorted[rank]
}

func main() {
	manifest := flag.String("manifest", "", "shared binary input manifest")
	samples := flag.Int("samples", 11, "individual calls per input")
	warmup := flag.Int("warmup", 1, "untimed calls per input")
	rawPath := flag.String("raw", "", "raw sample TSV path")
	flag.Parse()
	if *manifest == "" || *rawPath == "" || *samples < 1 || *warmup < 0 {
		fmt.Fprintln(os.Stderr, "usage: go-scaling -manifest inputs.tsv -samples N -warmup N -raw samples.tsv")
		os.Exit(2)
	}
	inputs, err := loadScaleInputs(*manifest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load scaling inputs:", err)
		os.Exit(2)
	}
	output := scaleOutput{Cases: make([]map[string]any, 0, len(inputs))}
	allSamples := make([]measured, 0, len(inputs))
	for _, input := range inputs {
		var detected bool
		var fingerprint string
		samples := make([]int64, *samples)
		for range *warmup {
			if input.api == "detect_sqli" {
				detected, fingerprint = libinjection.IsSQLi(input.data)
			} else {
				detected = libinjection.IsXSS(input.data)
			}
		}
		for index := range samples {
			start := time.Now()
			if input.api == "detect_sqli" {
				detected, fingerprint = libinjection.IsSQLi(input.data)
			} else {
				detected = libinjection.IsXSS(input.data)
			}
			samples[index] = time.Since(start).Nanoseconds()
		}
		sorted := append([]int64(nil), samples...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		output.Cases = append(output.Cases, map[string]any{
			"detector": input.detector, "api": input.api, "case": input.name, "input_bytes": input.size,
			"detected": detected, "fingerprint": hex.EncodeToString([]byte(fingerprint)), "median_ns": quantile(sorted, 50),
		})
		allSamples = append(allSamples, measured{samples: samples, detected: detected, fingerprint: hex.EncodeToString([]byte(fingerprint))})
	}
	raw, err := os.Create(*rawPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create raw samples:", err)
		os.Exit(2)
	}
	writer := bufio.NewWriter(raw)
	fmt.Fprintln(writer, "detector\tapi\tcase\tinput_bytes\titeration\tnanos\tdetected\tfingerprint")
	for index, input := range inputs {
		for iteration, nanos := range allSamples[index].samples {
			fmt.Fprintf(
				writer,
				"%s\t%s\t%s\t%d\t%d\t%d\t%t\t%s\n",
				input.detector,
				input.api,
				input.name,
				input.size,
				iteration,
				nanos,
				allSamples[index].detected,
				allSamples[index].fingerprint,
			)
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
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		fmt.Fprintln(os.Stderr, "write JSON result:", err)
		os.Exit(2)
	}
}
