package analyze

import (
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/opengraph"
	"github.com/lkarlslund/adalanche/modules/jsoncodec"
	"github.com/lkarlslund/adalanche/modules/ui"
)

const Loadername = "OpenGraph"

var (
	_ = engine.AddLoader(func() engine.Loader { return &OpenGraphLoader{} })
)

type loaderQueueItem struct {
	cb   engine.ProgressCallbackFunc
	path string
}

type OpenGraphLoader struct {
	target engine.LoadTarget
	queue  chan loaderQueueItem
	done   sync.WaitGroup
}

func (ld *OpenGraphLoader) Name() string {
	return Loadername
}
func (ld *OpenGraphLoader) Init(target engine.LoadTarget) error {
	ld.target = target
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
				var dec = jsoncodec.JSON.NewDecoder(r)
				err = dec.Decode(&ogd)
				if err != nil {
					ui.Warn().Msgf("Problem unmarshalling data from JSON file %v: %v", queueItem, err)
					continue
				}
				r.Close()

				tx := ld.target.BeginCollection("graph " + queueItem.path)
				err = processOpenGraphData(tx, ogd)
				if err == nil {
					err = tx.Commit()
				}
				if err != nil {
					ui.Warn().Msgf("Problem importing collector info: %v", err)
					continue
				}
			}
			ld.done.Done()
		}()
	}
	return nil
}
func (ld *OpenGraphLoader) Close() error {
	close(ld.queue)
	ld.done.Wait()
	return nil
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
