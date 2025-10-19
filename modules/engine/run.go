package engine

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"slices"
	"sync"
	"time"

	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/gonk"
)

// Loads, processes and merges everything. It's magic, just in code
func Run(paths ...string) (*IndexedGraph, error) {
	starttime := time.Now()

	var activeLoaders []Loader
	gonk.SetGrowStrategy(gonk.Double)

	overallprogress := ui.ProgressBar("Loading and analyzing", 8)

	for _, lg := range loadergenerators {
		loader := lg()

		ui.Debug().Msgf("Initializing loader for %v", loader.Name())
		err := loader.Init()
		if err != nil {
			ui.Fatal().Msgf("Loader %v init failure: %v", loader.Name(), err.Error())
		}
		activeLoaders = append(activeLoaders, loader)
	}

	// Load everything
	loadbar := ui.ProgressBar("Loading data", 0)

	var allLoaderGraphs []loaderGraphInfo

	// Process each data folder
	los, err := loadWithLoaders(activeLoaders, paths, func(cur, max int) {
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
	allLoaderGraphs = append(allLoaderGraphs, los...)
	loadbar.Finish()

	overallprogress.Add(1)

	var preprocessWG sync.WaitGroup
	var graphsToMerge []*IndexedGraph
	for _, os := range allLoaderGraphs {
		if os.Objects.Order() < 2 {
			// Don't bother with empty objects
			continue
		}

		graphsToMerge = append(graphsToMerge, os.Objects)

		// Pimp my performance speedup
		os.Objects.BulkLoadEdges(true)

		preprocessWG.Add(1)
		go func(lobj loaderGraphInfo) {
			var loaderid LoaderID
			for i, loader := range activeLoaders {
				if loader == lobj.Loader {
					loaderid = LoaderID(i)
					break
				}
			}

			for priority := BeforeMergeLow; priority <= BeforeMergeFinal; priority++ {
				status := fmt.Sprintf("Preprocessing %v priority %v with %v objects", lobj.Loader.Name(), priority.String(), lobj.Objects.Order())
				ui.Debug().Msg(status)
				Process(lobj.Objects, status, loaderid, priority)
				lobj.Objects.FlushEdges()
			}

			preprocessWG.Done()
		}(os)
	}
	preprocessWG.Wait()

	runtime.GC()
	debug.FreeOSMemory()
	overallprogress.Add(1)

	// Merging all subgraphs into the globalGraph
	globalGraph, err := MergeGraphs(graphsToMerge)
	if err != nil {
		return nil, err
	}

	// Free background processes so we can get rid of everything
	for _, g := range graphsToMerge {
		g.BulkLoadEdges(false)
	}

	clear(graphsToMerge)
	clear(allLoaderGraphs)
	runtime.GC()
	debug.FreeOSMemory()

	overallprogress.Add(1)

	for priority := AfterMergeLow; priority <= AfterMergeFinal; priority++ {
		PostProcess(globalGraph, priority)
		runtime.GC()
		overallprogress.Add(1)
	}

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

func PostProcess(ao *IndexedGraph, priority ProcessPriority) {
	starttime := time.Now()

	// Do global post-processing
	Process(ao, fmt.Sprintf("Postprocessing priority %v", priority.String()), -1, priority)
	ao.FlushEdges()

	ui.Info().Msgf("Time to finish post-processing %v", time.Since(starttime))
}
