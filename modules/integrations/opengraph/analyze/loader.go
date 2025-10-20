package analyze

import (
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/bytedance/sonic"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/opengraph"
	"github.com/lkarlslund/adalanche/modules/ui"
)

const Loadername = "OpenGraph"

var (
	loader = engine.AddLoader(func() engine.Loader { return &OpenGraphLoader{} })
)

type loaderQueueItem struct {
	cb   engine.ProgressCallbackFunc
	path string
}

type OpenGraphLoader struct {
	graphs []*engine.IndexedGraph
	queue  chan loaderQueueItem
	done   sync.WaitGroup
	mutex  sync.Mutex
}

func (ld *OpenGraphLoader) Name() string {
	return Loadername
}
func (ld *OpenGraphLoader) Init() error {
	ld.queue = make(chan loaderQueueItem, 128)
	for i := 0; i < runtime.NumCPU(); i++ {
		ld.done.Add(1)
		go func() {
			for queueItem := range ld.queue {
				r, err := os.Open(queueItem.path)
				if err != nil {
					ui.Warn().Msgf("Problem reading data from JSON file %v: %v", queueItem, err)
					continue
				}

				var ogd opengraph.Model
				var dec = sonic.ConfigDefault.NewDecoder(r)
				err = dec.Decode(&ogd)
				if err != nil {
					ui.Warn().Msgf("Problem unmarshalling data from JSON file %v: %v", queueItem, err)
					continue
				}
				r.Close()

				g := engine.NewLoaderObjects(ld)
				g.BulkLoadEdges(true)
				err = processOpenGraphData(g, ogd)
				g.BulkLoadEdges(false)

				if err != nil {
					ui.Warn().Msgf("Problem importing collector info: %v", err)
					continue
				}

				ld.mutex.Lock()
				ld.graphs = append(ld.graphs, g)
				ld.mutex.Unlock()
			}
			ld.done.Done()
		}()
	}
	return nil
}
func (ld *OpenGraphLoader) Close() ([]*engine.IndexedGraph, error) {
	close(ld.queue)
	ld.done.Wait()

	return ld.graphs, nil
}

func (ld *OpenGraphLoader) Load(path string, cb engine.ProgressCallbackFunc) error {
	if !strings.HasSuffix(path, opengraph.Suffix) {
		return engine.ErrUninterested
	}
	ld.queue <- loaderQueueItem{
		path: path,
		cb:   cb,
	}
	return nil
}
