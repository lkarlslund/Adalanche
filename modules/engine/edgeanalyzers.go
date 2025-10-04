package engine

import (
	"sync"

	"github.com/lkarlslund/adalanche/modules/ui"
)

//go:generate go tool github.com/dmarkham/enumer -type=ProcessPriority -output enums.go

type ProgressCallbackFunc func(progress int, totalprogress int)

type ProcessorFunc func(ao *IndexedGraph)

type ProcessPriority int

const (
	BeforeMergeLow ProcessPriority = iota
	BeforeMerge
	BeforeMergeHigh
	BeforeMergeFinal
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

// LoaderID = wildcard
func Process(ao *IndexedGraph, statustext string, l LoaderID, priority ProcessPriority) error {
	var priorityProcessors []ppfInfo
	for _, potentialProcessor := range registeredProcessors {
		if (potentialProcessor.loader == l || l == -1) && potentialProcessor.priority == priority {
			priorityProcessors = append(priorityProcessors, potentialProcessor)
		}
	}

	aoLen := ao.Order()
	total := len(priorityProcessors) * aoLen

	if total == 0 {
		return nil
	}

	// We need to process this many objects
	pb := ui.ProgressBar(statustext, int64(total))
	var wg sync.WaitGroup
	for _, processor := range priorityProcessors {
		wg.Add(1)
		go func(ppf ppfInfo) {
			ppf.pf(ao)
			pb.Add(int64(aoLen))
			wg.Done()
		}(processor)
	}
	wg.Wait()
	pb.Finish()

	return nil
}
