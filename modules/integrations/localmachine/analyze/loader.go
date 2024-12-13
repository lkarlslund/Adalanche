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

var (
	loader = engine.AddLoader(func() engine.Loader { return &LocalMachineLoader{} })
)

type loaderQueueItem struct {
	cb   engine.ProgressCallbackFunc
	path string
}

type LocalMachineLoader struct {
	ao          *engine.Objects
	machinesids map[string]*engine.ObjectSlice
	infostoadd  chan loaderQueueItem
	done        sync.WaitGroup
	mutex       sync.Mutex
}

func (ld *LocalMachineLoader) Name() string {
	return Loadername
}
func (ld *LocalMachineLoader) Init() error {
	ld.ao = engine.NewLoaderObjects(ld)
	ld.machinesids = make(map[string]*engine.ObjectSlice)
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
				defer r.Close()

				var cinfo localmachine.Info
				var dec = sonic.ConfigDefault.NewDecoder(r)
				err = dec.Decode(&cinfo)
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
					sids := ld.machinesids[cinfo.Machine.LocalSID]
					if sids == nil {
						slice := engine.NewObjectSlice(0)
						sids = &slice
						ld.machinesids[cinfo.Machine.LocalSID] = sids
					}
					sids.Add(computerobject)
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

	if ld.ao.Len() == 1 {
		return nil, nil // nothing generated
	}

	// Knot all the objects with colliding SIDs together
	for _, os := range ld.machinesids {
		os.Iterate(func(o *engine.Object) bool {
			os.Iterate(func(p *engine.Object) bool {
				if o != p {
					o.EdgeTo(p, EdgeSIDCollision)
				}
				return true
			})
			return true
		})
	}

	return []*engine.Objects{ld.ao}, nil
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
