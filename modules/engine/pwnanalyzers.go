package engine

import (
	"sync"
	"time"

	"github.com/lkarlslund/adalanche/modules/ui"
)

var (
	loaderAnalyzers = map[LoaderID][]EdgeAnalyzer{}
)

func (l LoaderID) AddAnalyzers(pa ...EdgeAnalyzer) {
	loaderAnalyzers[l] = append(loaderAnalyzers[l], pa...)
}

func (l LoaderID) Analyze(ao *Objects, cb ProgressCallbackFunc) {
	if len(loaderAnalyzers[l]) == 0 {
		return
	}

	objectslice := ao.Slice()
	max := ao.Len() * len(loaderAnalyzers[l])
	cb(0, max)

	timings := make([]time.Time, len(loaderAnalyzers[l]))

	ao.SetThreadsafe(true)

	starttime := time.Now()
	var wait sync.WaitGroup

	for i, an := range loaderAnalyzers[l] {
		wait.Add(1)
		go func(li int, lan EdgeAnalyzer) {
			for _, o := range objectslice {
				lan.ObjectAnalyzer(o, ao)
				cb(-1, 0)
			}
			timings[li] = time.Now()
			wait.Done()
		}(i, an)
	}
	wait.Wait()

	endtime := time.Now()

	ao.SetThreadsafe(false)

	for i := range loaderAnalyzers[l] {
		ui.Debug().Msgf("Elapsed %vms for analysis %v", timings[i].Sub(starttime).Milliseconds(), loaderAnalyzers[l][i].Description)
	}
	ui.Info().Msgf("Total elapsed %vms for %v analysis runs on %v objects", endtime.Sub(starttime).Milliseconds(), len(loaderAnalyzers[l]), len(objectslice))
}

type ProgressCallbackFunc func(progress int, totalprogress int)

type ProcessorFunc func(ao *Objects)

type ProcessPriority int

const (
	BeforeMergeLow ProcessPriority = iota
	BeforeMerge
	BeforeMergeHigh
	AfterMergeLow
	AfterMerge
	AfterMergeHigh
	AfterMergeFinal
)

type ppfInfo struct {
	pf          ProcessorFunc
	description string
	priority    ProcessPriority
	loader      LoaderID
}

var registeredProcessors []ppfInfo

func (l LoaderID) AddProcessor(pf ProcessorFunc, description string, priority ProcessPriority) {
	registeredProcessors = append(registeredProcessors, ppfInfo{
		loader:      l,
		description: description,
		pf:          pf,
		priority:    priority,
	})
}

func Process(ao *Objects, cb ProgressCallbackFunc, l LoaderID, priority ProcessPriority) error {
	var priorityProcessors []ppfInfo
	for _, potentialProcessor := range registeredProcessors {
		if potentialProcessor.loader == l && potentialProcessor.priority == priority {
			priorityProcessors = append(priorityProcessors, potentialProcessor)
		}
	}

	total := len(priorityProcessors) * ao.Len()

	if total == 0 {
		return nil
	}

	// We need to process this many objects
	cb(0, total)

	for _, processor := range priorityProcessors {
		processor.pf(ao)
		cb(-ao.Len(), 0)
	}

	return nil // FIXME
}
