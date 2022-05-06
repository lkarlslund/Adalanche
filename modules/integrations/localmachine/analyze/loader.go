package analyze

import (
	"io/ioutil"
	"runtime"
	"strings"
	"sync"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"github.com/mailru/easyjson"
	"github.com/rs/zerolog/log"
)

const loadername = "LocalMachine JSON file"

var (
	loader = engine.AddLoader(func() engine.Loader { return &LocalMachineLoader{} })
)

type LocalMachineLoader struct {
	ao          *engine.Objects
	done        sync.WaitGroup
	mutex       sync.Mutex
	machinesids map[windowssecurity.SID][]*engine.Object
	infostoadd  chan string
}

func (ld *LocalMachineLoader) Name() string {
	return loadername
}

func (ld *LocalMachineLoader) Init() error {
	ld.ao = engine.NewLoaderObjects(ld)
	ld.ao.SetThreadsafe(true)
	ld.machinesids = make(map[windowssecurity.SID][]*engine.Object)
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
				err = ld.ImportCollectorInfo(cinfo)
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

func (ld *LocalMachineLoader) Close() ([]*engine.Objects, error) {
	close(ld.infostoadd)
	ld.done.Wait()
	ld.ao.SetThreadsafe(false)

	for _, o := range ld.ao.Slice() {
		if o.HasAttr(activedirectory.ObjectSid) && o.HasAttr(engine.UniqueSource) {

			// We can do this with confidence as everything comes from this loader
			sidwithoutrid := o.OneAttrRaw(activedirectory.ObjectSid).(windowssecurity.SID).StripRID()

			switch o.Type() {
			case engine.ObjectTypeComputer:
				// We don't link that - it's either absorbed into the real computer object, or it's orphaned
			case engine.ObjectTypeUser:
				// It's a User we added, find the computer
				if computer, found := ld.ao.FindTwo(
					engine.UniqueSource, o.OneAttr(engine.UniqueSource),
					LocalMachineSID, engine.AttributeValueSID(sidwithoutrid)); found {
					o.ChildOf(computer) // FIXME -> Users
				}
			case engine.ObjectTypeGroup:
				// It's a Group we added
				if computer, found := ld.ao.FindTwo(
					engine.UniqueSource, o.OneAttr(engine.UniqueSource),
					LocalMachineSID, engine.AttributeValueSID(sidwithoutrid)); found {
					o.ChildOf(computer) // FIXME -> Groups
				}
			default:
				// if o.HasAttr(activedirectory.ObjectSid) {
				// 	if computer, found := ld.ao.FindTwo(
				// 		engine.UniqueSource, o.OneAttr(engine.UniqueSource),
				// 		LocalMachineSID, engine.AttributeValueSID(sidwithoutrid)); found {
				// 		o.ChildOf(computer) // We don't know what it is
				// 	}
				// }
			}
		}
	}

	// Knot all the objects with colliding SIDs together
	for _, os := range ld.machinesids {
		for _, o := range os {
			for _, p := range os {
				if o != p {
					p.Pwns(o, PwnSIDCollision)
					o.Pwns(p, PwnSIDCollision)
				}
			}
		}
	}

	result := []*engine.Objects{ld.ao}
	ld.ao = nil
	return result, nil
}

func (ld *LocalMachineLoader) Load(path string, cb engine.ProgressCallbackFunc) error {
	if !strings.HasSuffix(path, localmachine.Suffix) {
		return engine.ErrUninterested
	}

	ld.infostoadd <- path
	return nil
}
