package main

import (
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/lkarlslund/adalanche/modules/engine"
)

// TestDatasetProcessorTimings loads the dataset in ADALANCHE_TEST_DATA and
// prints how long each processor took in total, as "TIMING" lines.
func TestDatasetProcessorTimings(t *testing.T) {
	path := os.Getenv("ADALANCHE_TEST_DATA")
	if path == "" {
		t.Skip("ADALANCHE_TEST_DATA is not set")
	}
	if _, err := engine.Run(path); err != nil {
		t.Fatal("loading failed")
	}
	type key struct {
		phase       engine.Phase
		description string
	}
	totals := map[key]time.Duration{}
	for _, timing := range engine.ProcessorTimings() {
		totals[key{timing.Phase, timing.Description}] += timing.Duration
	}
	keys := make([]key, 0, len(totals))
	for k := range totals {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b key) int { return int(totals[b] - totals[a]) })
	for _, k := range keys {
		fmt.Printf("TIMING %.3f %q %q\n", totals[k].Seconds(), k.phase.String(), k.description)
	}
}
