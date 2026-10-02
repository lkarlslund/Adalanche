package analyze

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/lkarlslund/adalanche/modules/collection"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
)

var (
	gposource = engine.NV("Group Policy")
	GLoader   = engine.AddLoader(func() engine.Loader { return (&GPOLoader{}) })
)

type GPOLoader struct {
	failed    atomic.Uint64
	target    engine.LoadTarget
	fileQueue chan string
	done      sync.WaitGroup
}

func (ld *GPOLoader) Name() string {
	return gposource.String()
}

func (ld *GPOLoader) Init(target engine.LoadTarget) error {
	ld.target = target
	ld.fileQueue = make(chan string, 8192)
	// GPO objects
	for i := 0; i < min(runtime.GOMAXPROCS(0), 4); i++ {
		ld.done.Add(1)
		go func() {
			for path := range ld.fileQueue {
				ginfo, err := activedirectory.ReadGPOCollection(path)
				if err != nil {
					ld.failed.Add(1)
					ui.Warn().Msgf("Problem reading policy collection %v: %v", path, err)
					continue
				}
				// Each policy collection is one load transaction, committed
				// only when the import succeeds.
				tx := ld.target.BeginCollection("policy " + ginfo.Path)
				err = importGPOInfo(ginfo, tx)
				if err == nil {
					err = tx.Commit()
				}
				if err != nil {
					ld.failed.Add(1)
					ui.Warn().Msgf("Problem importing GPO: %v", err)
					continue
				}
			}
			ld.done.Done()
		}()
	}
	return nil
}
func (ld *GPOLoader) Load(path string, cb engine.ProgressCallbackFunc) error {
	if strings.HasSuffix(path, ".gpodata.json") || strings.HasSuffix(path, collection.GPOSuffix) {
		ld.fileQueue <- path
		return nil
	}
	return engine.ErrUninterested
}
func (ld *GPOLoader) Close() error {
	close(ld.fileQueue)
	ld.done.Wait()

	if failures := ld.failed.Load(); failures != 0 {
		return fmt.Errorf("%d policy collections failed to import", failures)
	}
	return nil
}
