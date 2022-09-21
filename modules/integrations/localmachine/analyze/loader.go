package analyze

import (
	"io/ioutil"
	"runtime"
	"strings"
	"sync"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/mailru/easyjson"
)

const loadername = "LocalMachine JSON file"

var (
	loader = engine.AddLoader(func() engine.Loader { return &LocalMachineLoader{} })
)

type loaderQueueItem struct {
	path string
	cb   engine.ProgressCallbackFunc
}

type LocalMachineLoader struct {
	ao          *engine.Objects
	done        sync.WaitGroup
	mutex       sync.Mutex
	machinesids map[string][]*engine.Object
	infostoadd  chan loaderQueueItem
}

func (ld *LocalMachineLoader) Name() string {
	return loadername
}

func (ld *LocalMachineLoader) Init() error {
	ld.ao = engine.NewLoaderObjects(ld)
	ld.ao.SetThreadsafe(true)
	ld.machinesids = make(map[string][]*engine.Object)
	ld.infostoadd = make(chan loaderQueueItem, 128)

	for i := 0; i < runtime.NumCPU(); i++ {
		ld.done.Add(1)
		go func() {
			for queueItem := range ld.infostoadd {
				raw, err := ioutil.ReadFile(queueItem.path)
				if err != nil {
					ui.Warn().Msgf("Problem reading data from JSON file %v: %v", queueItem, err)
					continue
				}

				var cinfo localmachine.Info
				err = easyjson.Unmarshal(raw, &cinfo)
				if err != nil {
					ui.Warn().Msgf("Problem unmarshalling data from JSON file %v: %v", queueItem, err)
					continue
				}

				// ld.infoaddmutex.Lock()
				computerobject, err := ImportCollectorInfo(ld.ao, cinfo)
				if err != nil {
					ui.Warn().Msgf("Problem importing collector info: %v", err)
					continue
				}

				if cinfo.Machine.LocalSID != "" {
					ld.mutex.Lock()
					ld.machinesids[cinfo.Machine.LocalSID] = append(ld.machinesids[cinfo.Machine.LocalSID], computerobject)
					ld.mutex.Unlock()
				}

				// Add progress
				queueItem.cb(-100, 0)
			}
			ld.done.Done()
		}()
	}

	return nil
}

func (ld *LocalMachineLoader) Close() ([]*engine.Objects, error) {
	close(ld.infostoadd)
	ld.done.Wait()
	ld.ao.SetThreadsafe(false)

	// Knot all the objects with colliding SIDs together
	for _, os := range ld.machinesids {
		for _, o := range os {
			for _, p := range os {
				if o != p {
					o.EdgeTo(p, EdgeSIDCollision)
				}
			}
		}
	}

	result := []*engine.Objects{ld.ao}
	ld.ao = nil
	return result, nil
}

func (ld *LocalMachineLoader) Estimate(path string, cb engine.ProgressCallbackFunc) error {
	if !strings.HasSuffix(path, localmachine.Suffix) {
		return engine.ErrUninterested
	}

	// Estimate progress
	cb(0, -100)
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
