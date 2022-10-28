package engine

import (
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/adalanche/modules/dedup"
	"github.com/lkarlslund/adalanche/modules/ui"
)

// Loads, processes and merges everything. It's magic, just in code
func Run(path string) (*Objects, error) {
	starttime := time.Now()

	var loaders []Loader

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

	// Enable deduplication
	// DedupValues(true)

	lo, err := Load(loaders, path, func(cur, max int) {
		if max > 0 {
			loadbar.ChangeMax(max)
		} else if max < 0 {
			loadbar.ChangeMax(loadbar.GetMax() + (-max))
		}
		if cur > 0 {
			loadbar.Set(cur)
		} else {
			loadbar.Add(-cur)
		}
	})
	if err != nil {
		return nil, err
	}
	loadbar.Finish()

	var preprocessWG sync.WaitGroup
	for _, os := range lo {
		if os.Objects.Len() == 0 {
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
				Process(lobj.Objects, fmt.Sprintf("Preprocessing %v priority %v", lobj.Loader.Name(), priority.String()), loaderid, priority)
			}

			preprocessWG.Done()
		}(os)
	}
	preprocessWG.Wait()

	// Merging
	objs := make([]*Objects, len(lo))
	for i, lobj := range lo {
		objs[i] = lobj.Objects
	}
	ao, err := Merge(objs)

	ui.Info().Msgf("Time to UI done in %v", time.Since(starttime))

	// Do global post-processing
	go func() {
		for priority := AfterMergeLow; priority <= AfterMergeFinal; priority++ {
			Process(ao, fmt.Sprintf("Postprocessing global objects priority %v", priority.String()), -1, priority)
		}

		// Free deduplication map
		// DedupValues(false)

		ui.Info().Msgf("Time to analysis completed done in %v", time.Since(starttime))

		var statarray []string
		for stat, count := range ao.Statistics() {
			if stat == 0 {
				continue
			}
			if count == 0 {
				continue
			}
			statarray = append(statarray, fmt.Sprintf("%v: %v", ObjectType(stat).String(), count))
		}
		ui.Info().Msg(strings.Join(statarray, ", "))

		// Show debug counters
		var pwnarray []string
		for pwn, count := range EdgePopularity {
			if count == 0 {
				continue
			}
			pwnarray = append(pwnarray, fmt.Sprintf("%v: %v", Edge(pwn).String(), count))
		}
		ui.Debug().Msg(strings.Join(pwnarray, ", "))

		dedupStats := dedup.D.Statistics()

		ui.Debug().Msgf("Deduplicator stats: %v items added using %v bytes in memory", dedupStats.ItemsAdded, dedupStats.BytesInMemory)
		ui.Debug().Msgf("Deduplicator stats: %v items not allocated saving %v bytes of memory", dedupStats.ItemsSaved, dedupStats.BytesSaved)
		ui.Debug().Msgf("Deduplicator stats: %v items removed (memory stats unavailable)", dedupStats.ItemsRemoved)
		ui.Debug().Msgf("Deduplicator stats: %v collisions detected (first at %v objects)", dedupStats.Collisions, dedupStats.FirstCollisionDetected)
		ui.Debug().Msgf("Deduplicator stats: %v keepalive objects added", dedupStats.KeepAliveItemsAdded)
		ui.Debug().Msgf("Deduplicator stats: %v keepalive objects removed", dedupStats.KeepAliveItemsRemoved)

		// Try to recover some memory
		dedup.D.Flush()

		// objs.DropIndexes()

		// Force GC
		// runtime.GC()

		// After all this loading and merging, it's time to do release unused RAM
		debug.FreeOSMemory()

	}()

	return ao, err
}
