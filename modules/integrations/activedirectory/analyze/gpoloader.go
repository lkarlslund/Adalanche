package analyze

import (
	"encoding/json"
	"io/ioutil"
	"maps"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/util"
)

var (
	gposource = engine.NewAttributeValueString("Group Policy")
	GLoader   = engine.AddLoader(func() engine.Loader { return (&GPOLoader{}) })
)

type GPOLoader struct {
	dco              map[string]*engine.Objects
	gpofiletoprocess chan string
	done             sync.WaitGroup
	importmutex      sync.Mutex
}

func (ld *GPOLoader) Name() string {
	return gposource.String()
}
func (ld *GPOLoader) Init() error {
	ld.dco = make(map[string]*engine.Objects)
	ld.gpofiletoprocess = make(chan string, 8192)
	// GPO objects
	for i := 0; i < runtime.NumCPU(); i++ {
		ld.done.Add(1)
		go func() {
			for path := range ld.gpofiletoprocess {
				raw, err := ioutil.ReadFile(path)
				if err != nil {
					ui.Warn().Msgf("Problem reading data from GPO JSON file %v: %v", path, err)
					continue
				}
				var ginfo activedirectory.GPOdump
				err = json.Unmarshal(raw, &ginfo)
				if err != nil {
					ui.Warn().Msgf("Problem unmarshalling data from JSON file %v: %v", path, err)
					continue
				}
				thisao := ld.getShard(path)
				netbios := ginfo.DomainNetbios
				if netbios == "" {
					// Fallback to extracting from the domain DN
					netbios = util.ExtractNetbiosFromBase(ginfo.DomainDN)
				}
				if netbios == "" {
					// Fallback to using path
					parts := strings.Split(ginfo.Path, "\\")
					sysvol := -1
					for i, part := range parts {
						if strings.EqualFold(part, "sysvol") {
							sysvol = i
							break
						}
					}
					if sysvol != -1 && len(parts) > sysvol+2 && strings.EqualFold(parts[sysvol+2], "policies") {
						netbios, _, _ = strings.Cut(parts[sysvol+1], ".")
					}
				}
				if netbios != "" {
					thisao.AddDefaultFlex(
						engine.DataSource, engine.NewAttributeValueString(netbios),
					)
				} else {
					ui.Error().Msgf("Loading GPO %v without tagging source, this will give merge problems", ginfo.Path)
				}
				err = ImportGPOInfo(ginfo, thisao)
				if err != nil {
					ui.Warn().Msgf("Problem importing GPO: %v", err)
					continue
				}
			}
			ld.done.Done()
		}()
	}
	return nil
}
func (ld *GPOLoader) getShard(path string) *engine.Objects {
	shard := filepath.Dir(path)
	lookupshard := shard
	var ao *engine.Objects
	ld.importmutex.Lock()
	ao = ld.dco[lookupshard]
	if ao == nil {
		ao = engine.NewLoaderObjects(ld)
		ld.dco[lookupshard] = ao
	}
	ld.importmutex.Unlock()
	return ao
}
func (ld *GPOLoader) Load(path string, cb engine.ProgressCallbackFunc) error {
	if strings.HasSuffix(path, ".gpodata.json") {
		ld.gpofiletoprocess <- path
		return nil
	}
	return engine.ErrUninterested
}
func (ld *GPOLoader) Close() ([]*engine.Objects, error) {
	close(ld.gpofiletoprocess)
	ld.done.Wait()

	return slices.Collect(maps.Values(ld.dco)), nil
}
