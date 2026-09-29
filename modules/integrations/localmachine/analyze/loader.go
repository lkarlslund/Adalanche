package analyze

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/lkarlslund/adalanche/modules/collection"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/ui"
)

const Loadername = "Local Machine"

const estimatedNodesGenerated = 1400

var (
	loader = engine.AddLoader(func() engine.Loader { return &LocalMachineLoader{} })
)

type loaderQueueItem struct {
	cb   engine.ProgressCallbackFunc
	path string
}

type LocalMachineLoader struct {
	failed     atomic.Uint64
	graphs     []*engine.IndexedGraph
	infostoadd chan loaderQueueItem
	done       sync.WaitGroup
	mutex      sync.Mutex
}

func (ld *LocalMachineLoader) Name() string {
	return Loadername
}
func (ld *LocalMachineLoader) Init() error {
	ld.infostoadd = make(chan loaderQueueItem, 128)
	for i := 0; i < min(runtime.GOMAXPROCS(0), 4); i++ {
		ld.done.Add(1)
		go func() {
			for queueItem := range ld.infostoadd {
				cinfo, extensions, err := localmachine.ReadCollection(queueItem.path)
				if err != nil {
					ld.failed.Add(1)
					ui.Warn().Msgf("Problem reading machine collection %v: %v", queueItem.path, err)
					continue
				}

				g := engine.NewLoaderObjects(ld)
				computerobject, err := ImportCollectorInfo(g, cinfo)

				if err != nil {
					ld.failed.Add(1)
					ui.Warn().Msgf("Problem importing collector info: %v", err)
					continue
				}

				if err := importCollectionExtensions(g, computerobject, cinfo, extensions); err != nil {
					ld.failed.Add(1)
					ui.Warn().Msgf("Problem importing machine extensions: %v", err)
					continue
				}
				ld.mutex.Lock()
				ld.graphs = append(ld.graphs, g)
				ld.mutex.Unlock()

				// Add progress
				queueItem.cb(-estimatedNodesGenerated, 0)
			}
			ld.done.Done()
		}()
	}
	return nil
}
func (ld *LocalMachineLoader) Close() ([]*engine.IndexedGraph, error) {
	close(ld.infostoadd)
	ld.done.Wait()

	if failures := ld.failed.Load(); failures != 0 {
		return ld.graphs, fmt.Errorf("%d machine collections failed to import", failures)
	}
	return ld.graphs, nil
}

func (ld *LocalMachineLoader) Estimate(path string, cb engine.ProgressCallbackFunc) error {
	if !strings.HasSuffix(path, localmachine.Suffix) && !strings.HasSuffix(path, collection.MachineSuffix) {
		return engine.ErrUninterested
	}
	// Estimate progress
	cb(0, -estimatedNodesGenerated)
	return nil
}

func (ld *LocalMachineLoader) Load(path string, cb engine.ProgressCallbackFunc) error {
	if !strings.HasSuffix(path, localmachine.Suffix) && !strings.HasSuffix(path, collection.MachineSuffix) {
		return engine.ErrUninterested
	}
	ld.infostoadd <- loaderQueueItem{
		path: path,
		cb:   cb,
	}
	return nil
}
