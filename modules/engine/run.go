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

	progress := newRunProgress()
	defer progress.finish()

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

	// Load everything. The loaders report files: a positive max sets the
	// total, a negative one adds to it; a positive cur sets the count, a
	// negative one adds to it.
	progress.stage("Loading files", shareLoading)
	var filesDone, filesTotal int
	err := loadWithLoaders(globalGraph, activeLoaders, paths, func(cur, max int) {
		if max > 0 {
			filesTotal = max
		} else if max < 0 {
			filesTotal -= max
		}
		if cur > 0 {
			filesDone = cur
		} else {
			filesDone -= cur
		}
		progress.within(filesDone, filesTotal)
	})
	if err != nil {
		return nil, err
	}
	timed("loading")

	progress.stage("Loader processors", shareLoaderProcessors)
	if err := runPhase(globalGraph, AnyLoader, LoaderPhase, progress.within); err != nil {
		return nil, fmt.Errorf("preprocessing: %w", err)
	}
	timed("loader processors")
	runtime.GC()
	debug.FreeOSMemory()
	timed("garbage collection")

	progress.stage("Resolving references", shareFinishingLoading)
	if err := globalGraph.finishLoading(progress.within); err != nil {
		return nil, err
	}
	timed("finishing loading")

	runtime.GC()
	debug.FreeOSMemory()
	timed("garbage collection")

	progress.stage("Analysis processors", shareAnalysis)
	postprocessStart := time.Now()
	if err := runPhase(globalGraph, AnyLoader, AnalysisPhase, progress.within); err != nil {
		return nil, err
	}
	ui.Info().Msgf("Time to finish post-processing %v", time.Since(postprocessStart))
	phaseStart = time.Now()
	runtime.GC()
	timed("garbage collection")

	progress.stage("Graph attributes", shareGraphAttributes)
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

	// After all this loading and analysis, release unused memory
	debug.FreeOSMemory()

	gonk.SetGrowStrategy(gonk.FourItems)

	return globalGraph, err
}
