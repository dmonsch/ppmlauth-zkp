package main

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestWriteRawLatenciesWritesCSV(t *testing.T) {
	path := filepath.Join(t.TempDir(), "raw.csv")

	compileTimes := []time.Duration{time.Microsecond}
	setupTimes := []time.Duration{2 * time.Microsecond}
	proveTimes := []time.Duration{3 * time.Microsecond, 4 * time.Microsecond}
	verifyTimes := []time.Duration{5 * time.Microsecond}

	if err := writeRawLatencies(
		path,
		compileTimes,
		setupTimes,
		proveTimes,
		verifyTimes,
	); err != nil {
		t.Fatalf("writeRawLatencies returned error: %v", err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open raw latencies file: %v", err)
	}
	defer file.Close()

	records, err := csv.NewReader(file).ReadAll()
	if err != nil {
		t.Fatalf("read raw latencies CSV: %v", err)
	}

	expected := [][]string{
		{"phase", "iteration", "latency_ns", "latency"},
		{"compile", "1", "1000", time.Microsecond.String()},
		{"setup", "1", "2000", (2 * time.Microsecond).String()},
		{"prove", "1", "3000", (3 * time.Microsecond).String()},
		{"prove", "2", "4000", (4 * time.Microsecond).String()},
		{"verify", "1", "5000", (5 * time.Microsecond).String()},
	}

	if !reflect.DeepEqual(records, expected) {
		t.Fatalf("unexpected records:\nwant: %#v\n got: %#v", expected, records)
	}
}
