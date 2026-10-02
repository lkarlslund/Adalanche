package engine

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"slices"
	"time"

	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/gonk"
)

// Loads, processes and merges everything. It's magic, just in code
func Run(paths ...string) (*IndexedGraph, error) {
	latestMemoryStatistics.Store(nil)
	starttime := time.Now()

	var activeLoaders []Loader
	gonk.SetGrowStrategy(gonk.Double)

	if err := ValidateProcessors(); err != nil {
		return nil, err
	}

	overallprogress := ui.ProgressBar("Loading and analyzing", 5)

	// One graph for everything: loaders write into it through load
	// transactions, each under its own root node.
	globalGraph := NewAnalysisGraph()

	for _, lg := range loadergenerators {
		loader := lg()

		ui.Debug().Msgf("Initializing loader for %v", loader.Name())
		target := newLoadTarget(globalGraph, LoaderID(len(activeLoaders)), loader.Name())
		err := loader.Init(target)
		if err != nil {
			ui.Fatal().Msgf("Loader %v init failure: %v", loader.Name(), err.Error())
		}
		activeLoaders = append(activeLoaders, loader)
	}

	phaseStart := time.Now()
	timed := func(phase string) {
		commits, waiting, holding := globalGraph.takeCommitStats()
		ui.Info().Msgf("Phase %v took %v (%v commits holding the commit lock %v, waiting for it %v)", phase, time.Since(phaseStart), commits, holding, waiting)
		phaseStart = time.Now()
	}

	// Load everything
	loadbar := ui.ProgressBar("Loading data", 0)
	err := loadWithLoaders(globalGraph, activeLoaders, paths, func(cur, max int) {
		if max > 0 {
			loadbar.ChangeMax(int64(max))
		} else if max < 0 {
			loadbar.ChangeMax(loadbar.GetMax() + int64(-max))
		}
		if cur > 0 {
			loadbar.Set(int64(cur))
		} else {
			loadbar.Add(int64(-cur))
		}
	})
	if err != nil {
		return nil, err
	}
	loadbar.Finish()
	overallprogress.Add(1)
	timed("loading")

	if err := RunPhase(globalGraph, AnyLoader, BeforeMerge); err != nil {
		return nil, fmt.Errorf("preprocessing: %w", err)
	}
	timed("before-merge processors")
	runtime.GC()
	debug.FreeOSMemory()
	overallprogress.Add(1)
	timed("garbage collection")

	if err := globalGraph.FinishLoading(); err != nil {
		return nil, err
	}
	timed("finishing loading")

	runtime.GC()
	debug.FreeOSMemory()
	timed("garbage collection")

	overallprogress.Add(1)

	postprocessStart := time.Now()
	if err := RunPhase(globalGraph, AnyLoader, AfterMerge); err != nil {
		return nil, err
	}
	ui.Info().Msgf("Time to finish post-processing %v", time.Since(postprocessStart))
	phaseStart = time.Now()
	runtime.GC()
	overallprogress.Add(1)
	timed("garbage collection")

	if err := calculateGraphAttributes(globalGraph); err != nil {
		return nil, err
	}
	timed("graph attributes")
	if err := finalizeGraph(globalGraph); err != nil {
		return nil, err
	}
	timed("finalizing")
	captureMemoryStatistics(globalGraph)
	ui.Info().Msgf("Time to UI done in %v", time.Since(starttime))

	type statentry struct {
		name  string
		count int
	}

	ui.Debug().Msgf("Object type popularity:")
	var statarray []statentry
	for ot, count := range globalGraph.Statistics() {
		if ot == 0 {
			continue
		}
		if count == 0 {
			continue
		}
		statarray = append(statarray, statentry{
			name:  NodeType(ot).String(),
			count: count,
		})
	}
	slices.SortFunc(statarray, func(a, b statentry) int { return b.count - a.count }) // reverse
	for _, se := range statarray {
		ui.Debug().Msgf("%v: %v", se.name, se.count)
	}

	// Show debug counters
	ui.Debug().Msgf("Edge type popularity:")
	var edgestats []statentry
	for edge, count := range EdgePopularity {
		if count == 0 {
			continue
		}
		edgestats = append(edgestats, statentry{
			name:  Edge(edge).String(),
			count: int(count),
		})
	}
	slices.SortFunc(edgestats, func(a, b statentry) int { return b.count - a.count })
	for _, se := range edgestats {
		ui.Debug().Msgf("%v: %v", se.name, se.count)
	}

	// Force GC
	runtime.GC()

	// After all this loading and merging, it's time to do release unused RAM
	debug.FreeOSMemory()

	gonk.SetGrowStrategy(gonk.FourItems)

	overallprogress.Add(1)
	overallprogress.Finish()

	return globalGraph, err
}
