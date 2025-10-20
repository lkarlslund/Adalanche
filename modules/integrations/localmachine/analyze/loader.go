package analyze

import (
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/bytedance/sonic"
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
	for i := 0; i < runtime.NumCPU(); i++ {
		ld.done.Add(1)
		go func() {
			for queueItem := range ld.infostoadd {
				r, err := os.Open(queueItem.path)
				if err != nil {
					ui.Warn().Msgf("Problem reading data from JSON file %v: %v", queueItem, err)
					continue
				}

				var cinfo localmachine.Info
				var dec = sonic.ConfigDefault.NewDecoder(r)
				err = dec.Decode(&cinfo)
				if err != nil {
					ui.Warn().Msgf("Problem unmarshalling data from JSON file %v: %v", queueItem, err)
					continue
				}
				r.Close()

				g := engine.NewLoaderObjects(ld)
				g.BulkLoadEdges(true)
				computerobject, err := ImportCollectorInfo(g, cinfo)
				g.BulkLoadEdges(false)

				_ = computerobject

				if err != nil {
					ui.Warn().Msgf("Problem importing collector info: %v", err)
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

	return ld.graphs, nil
}

func (ld *LocalMachineLoader) Estimate(path string, cb engine.ProgressCallbackFunc) error {
	if !strings.HasSuffix(path, localmachine.Suffix) {
		return engine.ErrUninterested
	}
	// Estimate progress
	cb(0, -estimatedNodesGenerated)
	return nil
}

func (ld *LocalMachineLoader) Load(path string, cb engine.ProgressCallbackFunc) error {
	if !strings.HasSuffix(path, localmachine.Suffix) {
		return engine.ErrUninterested
	}
	ld.infostoadd <- loaderQueueItem{
		path: path,
		cb:   cb,
	}
	return nil
}
