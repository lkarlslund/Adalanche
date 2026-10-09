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
	target     engine.LoadTarget
	infostoadd chan loaderQueueItem
	done       sync.WaitGroup
}

func (ld *LocalMachineLoader) Name() string {
	return Loadername
}
func (ld *LocalMachineLoader) Init(target engine.LoadTarget) error {
	ld.target = target
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

				tx := ld.target.BeginCollection("machine collection " + queueItem.path)
				computerobject, err := ImportCollectorInfo(tx, cinfo)

				if err != nil {
					ld.failed.Add(1)
					ui.Warn().Msgf("Problem importing collector info: %v", err)
					continue
				}

				if err := importCollectionExtensions(tx, computerobject, cinfo, extensions); err != nil {
					ld.failed.Add(1)
					ui.Warn().Msgf("Problem importing machine extensions: %v", err)
					continue
				}
				if err := tx.Commit(); err != nil {
					ld.failed.Add(1)
					ui.Warn().Msgf("Problem committing machine collection %v: %v", queueItem.path, err)
					continue
				}

				// Add progress
				queueItem.cb(-estimatedNodesGenerated, 0)
			}
			ld.done.Done()
		}()
	}
	return nil
}
func (ld *LocalMachineLoader) Close() error {
	close(ld.infostoadd)
	ld.done.Wait()

	if failures := ld.failed.Load(); failures != 0 {
		return fmt.Errorf("%d machine collections failed to import", failures)
	}
	return nil
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
