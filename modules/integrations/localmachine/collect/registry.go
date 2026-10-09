package collect

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/lkarlslund/adalanche/modules/basedata"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/version"
)

// Stage orders collectors. Collectors in one stage run in parallel; a stage
// starts after every merge from the previous stage has been applied.
type Stage int

const (
	// StageIdentity establishes the machine identity other collectors rely on.
	StageIdentity Stage = iota
	// StageInventory gathers independent inventory sections.
	StageInventory
	// StageAssessment gathers assessment categories and may read the inventory.
	StageAssessment
	// StageDerived evaluates the merged inventory and assessment records.
	StageDerived
	stageCount
)

var stageTimeouts = [stageCount]time.Duration{
	StageIdentity:   time.Minute,
	StageInventory:  10 * time.Minute,
	StageAssessment: 2 * time.Minute,
	StageDerived:    5 * time.Minute,
}

// ThreadMode states what a collector needs from its operating-system thread.
type ThreadMode int

const (
	// ThreadAny collectors may move between threads.
	ThreadAny ThreadMode = iota
	// ThreadLocked collectors run on one thread and manage their own COM apartment.
	ThreadLocked
	// ThreadCOM collectors run on one thread joined to the multithreaded COM apartment.
	ThreadCOM
)

// Collector is one self-registered part of local machine collection.
type Collector struct {
	Name  string
	Stage Stage
	// Category names the assessment category this collector produces. The
	// category is selectable on the command line and, when not selected, is
	// recorded as not requested without running the collector.
	Category string
	Thread   ThreadMode
	// Timeout abandons a collector that has not returned; 0 uses the stage default.
	Timeout time.Duration
	// Collect gathers data without modifying anything outside its own locals and
	// env.Outcomes. The returned merge (or nil) publishes the data; merges run
	// one at a time and must replace, not modify, values in the result.
	Collect func(env *Env) (merge func(*Result))
}

// Env is what a running collector may use.
type Env struct {
	// Info and Assessment are read-only snapshots of earlier stages' merges.
	Info       *lm.Info
	Assessment *lm.Assessment
	// Outcomes records this collector's operation results.
	Outcomes basedata.CollectionResults
	// COMError is set for ThreadCOM collectors whose thread could not join COM.
	COMError error

	budget *assessmentBudget
}

// Result is the combined output of all collectors.
type Result struct {
	Info       lm.Info
	Assessment lm.Assessment
	// Extensions holds data owned by registered extensions, keyed by collector.
	Extensions map[string]any
}

var registeredCollectors []Collector

// RegisterCollector adds a collector. Call during package initialization.
func RegisterCollector(c Collector) {
	if c.Name == "" || c.Collect == nil || c.Stage < 0 || c.Stage >= stageCount {
		panic("invalid local machine collector registration")
	}
	if slices.ContainsFunc(registeredCollectors, func(existing Collector) bool {
		return existing.Name == c.Name || (c.Category != "" && existing.Category == c.Category)
	}) {
		panic(fmt.Sprintf("local machine collector %q registered twice", c.Name))
	}
	registeredCollectors = append(registeredCollectors, c)
}

func registeredCategories() []string {
	return registeredCategoriesOf(registeredCollectors)
}

// prepareThread sets up a job's thread; the platform file replaces it.
var prepareThread = func(ThreadMode) (cleanup func(), comErr error) { return func() {}, nil }

// Collect gathers local machine information with all registered collectors.
func Collect() (lm.Info, error) {
	result, err := CollectAll()
	return result.Info, err
}

// CollectAll gathers local machine information, including extension data.
func CollectAll() (Result, error) {
	if !platformSupported() {
		return Result{}, errors.New("this is not supported on this platform")
	}
	return runCollectors(registeredCollectors, effectiveCollectWorkers()), nil
}

func runCollectors(collectors []Collector, workers int) Result {
	r := Result{
		Info:       lm.Info{CollectionResults: basedata.CollectionResults{}},
		Assessment: lm.Assessment{Version: lm.AssessmentVersion, Captured: time.Now().UTC(), Categories: map[string]lm.AssessmentCapture{}},
		Extensions: map[string]any{},
	}
	budget := newAssessmentBudget(len(registeredCategoriesOf(collectors)))
	for stage := range stageCount {
		// Abandoned collectors may still read their snapshot, so merges from
		// this stage must never be visible through it.
		info := r.Info
		info.CollectionResults = nil
		assessment := r.Assessment
		assessment.Categories = maps.Clone(r.Assessment.Categories)
		var jobs []collectJob
		for _, c := range collectors {
			if c.Stage != stage {
				continue
			}
			if c.Category != "" && !AssessmentEnabled(c.Category) {
				r.Assessment.Categories[c.Category] = lm.AssessmentCapture{Result: basedata.CollectionResult{Status: basedata.CollectionNotRequested}}
				continue
			}
			timeout := c.Timeout
			if timeout == 0 {
				timeout = stageTimeouts[stage]
			}
			jobs = append(jobs, collectJob{name: c.Name, timeout: timeout, run: func(outcomes basedata.CollectionResults) func() {
				cleanup, comErr := prepareThread(c.Thread)
				defer cleanup()
				merge := c.Collect(&Env{Info: &info, Assessment: &assessment, Outcomes: outcomes, COMError: comErr, budget: budget})
				if merge == nil {
					return nil
				}
				return func() { merge(&r) }
			}})
		}
		runCollectJobs(jobs, workers, r.Info.CollectionResults)
	}
	for _, c := range collectors {
		// A category whose collector failed or was abandoned is still reported.
		if _, ok := r.Assessment.Categories[c.Category]; c.Category != "" && !ok {
			r.Assessment.Categories[c.Category] = lm.AssessmentCapture{Result: r.Info.CollectionResults[collectJobOutcomePrefix+c.Name]}
		}
	}
	for name, category := range r.Assessment.Categories {
		r.Info.CollectionResults["assessment/"+name] = category.Result
	}
	if raw, err := json.Marshal(r.Assessment); err == nil {
		r.Info.AssessmentData = string(raw)
	}
	r.Info.Common = basedata.Common{
		Collector: "collector",
		Version:   version.Version,
		Commit:    version.Commit,
		Collected: time.Now(),
	}
	return r
}

func registeredCategoriesOf(collectors []Collector) []string {
	var names []string
	for _, c := range collectors {
		if c.Category != "" {
			names = append(names, c.Category)
		}
	}
	return names
}
