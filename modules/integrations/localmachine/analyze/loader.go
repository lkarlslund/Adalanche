package analyze

import (
	"io/ioutil"
	"runtime"
	"strings"
	"sync"

	"github.com/lkarlslund/adalanche/modules/analyze"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/mailru/easyjson"
	"github.com/rs/zerolog/log"
	"github.com/schollz/progressbar/v3"
)

var (
	myloader    CollectorLoader
	dscollector = engine.AttributeValueString(myloader.Name())
)

func init() {
	analyze.RegisterLoader(&myloader)
}

type CollectorLoader struct {
	ao *engine.Objects

	infostoadd   chan string // filename
	infoaddmutex sync.Mutex
	done         sync.WaitGroup
}

func (ld *CollectorLoader) Name() string {
	return "Collector JSON file"
}

func (ld *CollectorLoader) Init(ao *engine.Objects) error {
	ao.SetThreadsafe(true)

	ld.ao = ao

	ld.infostoadd = make(chan string, 128)

	for i := 0; i < runtime.NumCPU(); i++ {
		ld.done.Add(1)
		go func() {
			for path := range ld.infostoadd {
				raw, err := ioutil.ReadFile(path)
				if err != nil {
					log.Warn().Msgf("Problem reading data from JSON file %v: %v", path, err)
					continue
				}

				var cinfo localmachine.Info
				err = easyjson.Unmarshal(raw, &cinfo)
				if err != nil {
					log.Warn().Msgf("Problem unmarshalling data from JSON file %v: %v", path, err)
					continue
				}

				// ld.infoaddmutex.Lock()
				err = ImportCollectorInfo(cinfo, ao)
				if err != nil {
					log.Warn().Msgf("Problem importing collector info: %v", err)
					continue
				}

				// ld.ao.AddMerge([]engine.Attribute{engine.ObjectSid}, generatedobjs...)
				// ld.infoaddmutex.Unlock()
			}
			ld.done.Done()
		}()
	}

	return nil
}

func (ld *CollectorLoader) Close() error {
	close(ld.infostoadd)
	ld.done.Wait()
	ld.ao.SetThreadsafe(false)
	return nil
}

func (ld *CollectorLoader) Load(path string, pb *progressbar.ProgressBar) error {
	if !strings.HasSuffix(path, localmachine.Suffix) {
		return analyze.UninterestedError
	}

	ld.infostoadd <- path
	return nil
}
