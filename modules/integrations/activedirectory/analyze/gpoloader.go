package analyze

import (
	"encoding/json"
	"io/ioutil"
	"runtime"
	"strings"
	"sync"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/rs/zerolog/log"
)

var (
	gposource = engine.AttributeValueString("Active Directory GPO loader")

	gpoloaderid = engine.AddLoader(&GPOLoader{})
)

type GPOLoader struct {
	done             sync.WaitGroup
	ao               *engine.Objects
	gpofiletoprocess chan string
}

func (ld *GPOLoader) Name() string {
	return gposource.String()
}

func (ld *GPOLoader) Init() error {
	ld.ao = engine.NewLoaderObjects(ld)
	ld.ao.SetThreadsafe(true)

	ld.gpofiletoprocess = make(chan string, 8192)

	for i := 0; i < runtime.NumCPU(); i++ {
		ld.done.Add(1)
		go func() {
			for path := range ld.gpofiletoprocess {
				raw, err := ioutil.ReadFile(path)
				if err != nil {
					log.Warn().Msgf("Problem reading data from GPO JSON file %v: %v", path, err)
					continue
				}

				var ginfo activedirectory.GPOdump
				err = json.Unmarshal(raw, &ginfo)
				if err != nil {
					log.Warn().Msgf("Problem unmarshalling data from JSON file %v: %v", path, err)
					continue
				}

				err = ImportGPOInfo(ginfo, ld.ao)
				if err != nil {
					log.Warn().Msgf("Problem importing GPO: %v", err)
					continue
				}
			}
			ld.done.Done()
		}()
	}

	return nil
}

func (ld *GPOLoader) Load(path string, cb engine.ProgressCallbackFunc) error {
	if !strings.HasSuffix(path, ".gpodata.json") {
		return engine.ErrUninterested
	}

	ld.gpofiletoprocess <- path
	return nil
}

func (ld *GPOLoader) Close() ([]*engine.Objects, error) {
	close(ld.gpofiletoprocess)
	ld.done.Wait()

	ld.ao.SetThreadsafe(false)

	return []*engine.Objects{ld.ao}, nil
}
