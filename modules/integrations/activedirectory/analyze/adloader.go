package analyze

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/lkarlslund/adalanche/modules/analyze"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/pierrec/lz4/v4"
	"github.com/rs/zerolog/log"
	"github.com/tinylib/msgp/msgp"
)

var (
	// FIXME - NEEDS TO ME TRUE AT THE MOMENT AS MAX_IMPORT IS BROKEN4
	importall = analyze.Command.Flags().Bool("importall", true, "Load all attributes from dump (expands search options, but at the cost of memory")

	adsource = engine.AttributeValueString("Active Directory dumps")
	Loader   = engine.AddLoader(&ADLoader{})
)

type convertqueueitem struct {
	object *activedirectory.RawObject
	ao     *engine.Objects
}

type ADLoader struct {
	importmutex      sync.Mutex
	done             sync.WaitGroup
	dco              map[string]*engine.Objects
	objectstoconvert chan convertqueueitem
	gpofiletoprocess chan string
	// domains          []domaininfo
	importall bool
}

type domaininfo struct {
	suffix      string
	netbiosname string
}

func (ld *ADLoader) Name() string {
	return adsource.String()
}

func (ld *ADLoader) Init() error {
	ld.importall = *importall

	ld.dco = make(map[string]*engine.Objects)
	ld.objectstoconvert = make(chan convertqueueitem, 8192)
	ld.gpofiletoprocess = make(chan string, 8192)

	// AD Objects
	for i := 0; i < runtime.NumCPU(); i++ {
		ld.done.Add(1)
		go func() {
			// chunk := make([]*engine.Object, 0, 64)
			for item := range ld.objectstoconvert {
				o := item.object.ToObject(ld.importall)

				// Here's a quirky workaround that will bite me later
				// Legacy well known objects in ForeignSecurityPrincipals gives us trouble with duplicate SIDs - skip them
				if strings.Count(o.OneAttrString(engine.ObjectSid), "-") == 3 && strings.Contains(o.OneAttrString(engine.DistinguishedName), "CN=ForeignSecurityPrincipals") {
					continue
				}

				item.ao.Add(o)
			}
			ld.done.Done()
		}()
	}

	// GPO objects
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

				thisao := ld.getShard(path, true)
				err = ImportGPOInfo(ginfo, thisao)
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

func (ld *ADLoader) getShard(path string, gpo bool) *engine.Objects {
	shard := filepath.Dir(path)

	lookupshard := shard
	if gpo {
		// Load GPO stuff into their own shard
		lookupshard += "_gpo"
	}

	var ao *engine.Objects
	ld.importmutex.Lock()
	ao = ld.dco[lookupshard]
	if ao == nil {
		ao = engine.NewLoaderObjects(ld)
		ao.AddDefaultFlex(engine.UniqueSource, engine.AttributeValueString(shard))
		ao.SetThreadsafe(true)
		ld.dco[lookupshard] = ao
	}
	ld.importmutex.Unlock()
	return ao
}

func (ld *ADLoader) Load(path string, cb engine.ProgressCallbackFunc) error {
	switch {
	case strings.HasSuffix(path, ".gpodata.json"):
		ld.gpofiletoprocess <- path
	case strings.HasSuffix(path, ".objects.msgp.lz4"):
		ao := ld.getShard(path, false)

		cachefile, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("Problem opening domain cache file: %v", err)
		}
		defer cachefile.Close()

		bcachefile := lz4.NewReader(cachefile)

		lz4options := []lz4.Option{lz4.ConcurrencyOption(-1)}
		bcachefile.Apply(lz4options...)

		d := msgp.NewReaderSize(bcachefile, 4*1024*1024)

		cachestat, _ := cachefile.Stat()

		divestimator := int64(1024) // 1kb ~ one object to load

		// We're approximating object count, by adding some stuff to max and then reporting on that
		cb(0, int(-cachestat.Size()/divestimator))

		// Load all the stuff
		var lastpos int64
		// justread := make([]byte, 4*1024*1024)
		var iteration uint32
		for {
			iteration++
			if iteration%1000 == 0 {
				pos, _ := cachefile.Seek(0, io.SeekCurrent)
				cb(int(-(pos-lastpos)/divestimator), 0) // Rounding errors, FIXME
				lastpos = pos
			}

			var rawObject activedirectory.RawObject
			err = rawObject.DecodeMsg(d)
			if err == nil {
				ld.objectstoconvert <- convertqueueitem{&rawObject, ao}
			} else if msgp.Cause(err) == io.EOF {
				return nil
			} else {
				return fmt.Errorf("Problem decoding object: %v", err)
			}
		}
	}
	return engine.ErrUninterested
}

func (ld *ADLoader) Close() ([]*engine.Objects, error) {
	close(ld.objectstoconvert)
	close(ld.gpofiletoprocess)
	ld.done.Wait()

	var aos []*engine.Objects
	for _, ao := range ld.dco {
		aos = append(aos, ao)
		ao.SetThreadsafe(false)
	}

	return aos, nil
}
