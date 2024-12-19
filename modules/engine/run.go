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
func Run(paths ...string) (*Objects, error) {
	starttime := time.Now()

	var loaders []Loader
	gonk.SetGrowStrategy(gonk.Double)

	overallprogress := ui.ProgressBar("Loading and analyzing", 8)

	for _, lg := range loadergenerators {
		loader := lg()

		ui.Debug().Msgf("Initializing loader for %v", loader.Name())
		err := loader.Init()
		if err != nil {
			ui.Fatal().Msgf("Loader %v init failure: %v", loader.Name(), err.Error())
		}
		loaders = append(loaders, loader)
	}

	// Load everything
	loadbar := ui.ProgressBar("Loading data", 0)

	var lo []loaderobjects
	for _, path := range paths {
		los, err := loadWithLoaders(loaders, path, func(cur, max int) {
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
		lo = append(lo, los...)
	}
	loadbar.Finish()

	overallprogress.Add(1)

	var preprocessWG sync.WaitGroup
	for _, os := range lo {
		if os.Objects.Len() < 2 {
			// Don't bother with empty objects
			continue
		}

		preprocessWG.Add(1)
		go func(lobj loaderobjects) {
			var loaderid LoaderID
			for i, loader := range loaders {
				if loader == lobj.Loader {
					loaderid = LoaderID(i)
					break
				}
			}

			for priority := BeforeMergeLow; priority <= BeforeMergeFinal; priority++ {
				status := fmt.Sprintf("Preprocessing %v priority %v with %v objects", lobj.Loader.Name(), priority.String(), lobj.Objects.Len())
				ui.Debug().Msg(status)
				Process(lobj.Objects, status, loaderid, priority)
			}

			preprocessWG.Done()
		}(os)
	}
	preprocessWG.Wait()

	runtime.GC()
	overallprogress.Add(1)

	// Merging
	objs := make([]*Objects, len(lo))
	for i, lobj := range lo {
		objs[i] = lobj.Objects
	}
	ao, err := Merge(objs)

	runtime.GC()
	overallprogress.Add(1)

	for priority := AfterMergeLow; priority <= AfterMergeFinal; priority++ {
		PostProcess(ao, priority)
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
	for ot, count := range ao.Statistics() {
		if ot == 0 {
			continue
		}
		if count == 0 {
			continue
		}
		statarray = append(statarray, statentry{
			name:  ObjectType(ot).String(),
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

	// objs.DropIndexes()

	ao.Iterate(func(obj *Object) bool {
		obj.edges[In].Optimize(gonk.Minimize)
		obj.edges[Out].Optimize(gonk.Minimize)
		return true
	})

	// Force GC
	runtime.GC()

	// After all this loading and merging, it's time to do release unused RAM
	debug.FreeOSMemory()

	gonk.SetGrowStrategy(gonk.FourItems)

	overallprogress.Add(1)
	overallprogress.Finish()

	return ao, err
}

func PostProcess(ao *Objects, priority ProcessPriority) {
	starttime := time.Now()

	// Do global post-processing
	Process(ao, fmt.Sprintf("Postprocessing priority %v", priority.String()), -1, priority)

	ui.Info().Msgf("Time to finish post-processing %v", time.Since(starttime))
}
