package analyze

import (
	"encoding/json"
	"maps"
	"os"
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
	gposource = engine.NV("Group Policy")
	GLoader   = engine.AddLoader(func() engine.Loader { return (&GPOLoader{}) })
)

type GPOLoader struct {
	graphs      map[string]*engine.IndexedGraph
	fileQueue   chan string
	done        sync.WaitGroup
	importMutex sync.Mutex
}

func (ld *GPOLoader) Name() string {
	return gposource.String()
}

func (ld *GPOLoader) Init() error {
	ld.graphs = make(map[string]*engine.IndexedGraph)
	ld.fileQueue = make(chan string, 8192)
	// GPO objects
	for i := 0; i < runtime.NumCPU(); i++ {
		ld.done.Add(1)
		go func() {
			for path := range ld.fileQueue {
				raw, err := os.ReadFile(path)
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
				g := ld.getShard(path)
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
				/*				if netbios != "" {
									g.AddDefaultFlex(
										engine.DataSource, engine.NV(netbios),
									)
								} else {
									ui.Error().Msgf("Loading GPO %v without tagging source, this will give merge problems", ginfo.Path)
								} */
				err = ImportGPOInfo(ginfo, g)
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
func (ld *GPOLoader) getShard(path string) *engine.IndexedGraph {
	shard := filepath.Dir(path)
	lookupshard := shard
	var g *engine.IndexedGraph
	ld.importMutex.Lock()
	g = ld.graphs[lookupshard]
	if g == nil {
		g = engine.NewLoaderObjects(ld)
		ld.graphs[lookupshard] = g
	}
	ld.importMutex.Unlock()
	return g
}
func (ld *GPOLoader) Load(path string, cb engine.ProgressCallbackFunc) error {
	if strings.HasSuffix(path, ".gpodata.json") {
		ld.fileQueue <- path
		return nil
	}
	return engine.ErrUninterested
}
func (ld *GPOLoader) Close() ([]*engine.IndexedGraph, error) {
	close(ld.fileQueue)
	ld.done.Wait()

	return slices.Collect(maps.Values(ld.graphs)), nil
}
