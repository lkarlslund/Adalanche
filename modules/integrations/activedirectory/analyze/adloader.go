package analyze

import (
	"fmt"
	"io"
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
	importcnf = analyze.Command.Flags().Bool("importcnf", false, "Import CNF (conflict) objects (experimental)")

	adsource = engine.AttributeValueString("Active Directory dumps")
	Loader   = engine.AddLoader(func() engine.Loader { return (&ADLoader{}) })
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
	importcnf        bool
}

type domaininfo struct {
	suffix      string
	netbiosname string
}

func (ld *ADLoader) Name() string {
	return adsource.String()
}

func (ld *ADLoader) Init() error {
	ld.importcnf = *importcnf

	ld.dco = make(map[string]*engine.Objects)
	ld.objectstoconvert = make(chan convertqueueitem, 8192)

	// AD Objects
	for i := 0; i < runtime.NumCPU(); i++ {
		ld.done.Add(1)
		go func() {
			// chunk := make([]*engine.Object, 0, 64)
			for item := range ld.objectstoconvert {
				o := item.object.ToObject()

				if !ld.importcnf && strings.Contains(o.DN(), "\\0ACNF:") {
					continue // skip conflict object
				}

				if !o.HasAttr(engine.ObjectClass) {
					if strings.Contains(o.DN(), ",CN=MicrosoftDNS,") {
						log.Debug().Msgf("Hardened DNS object without objectclass detected: %v", o.DN())
					} else {
						log.Warn().Msgf("Hardened object without objectclass detected: %v. This *might* affect your analysis, depending on object.", o.DN())
					}
				}

				item.ao.Add(o)
			}
			ld.done.Done()
		}()
	}

	return nil
}

func (ld *ADLoader) getShard(path string) *engine.Objects {
	shard := filepath.Dir(path)

	lookupshard := shard

	var ao *engine.Objects
	ld.importmutex.Lock()
	ao = ld.dco[lookupshard]
	if ao == nil {
		ao = engine.NewLoaderObjects(ld)
		// ao.AddDefaultFlex(engine.UniqueSource, engine.AttributeValueString(shard))
		ao.SetThreadsafe(true)
		ld.dco[lookupshard] = ao
	}
	ld.importmutex.Unlock()
	return ao
}

func (ld *ADLoader) Load(path string, cb engine.ProgressCallbackFunc) error {
	if strings.HasSuffix(path, ".objects.msgp.lz4") {
		ao := ld.getShard(path)

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
	ld.done.Wait()

	var aos []*engine.Objects
	for _, ao := range ld.dco {
		// Replace shard path value with the NETBIOS domain name
		// This allows merging with localmachine data for accounts that are in the same domain
		domobj, found := ao.FindTwo(engine.ObjectClass, engine.AttributeValueString("domainDNS"),
			engine.IsCriticalSystemObject, engine.AttributeValueString("true"))

		if found {
			netbiosdomain := domobj.Attr(engine.Name)
			for _, o := range ao.Slice() {
				o.Set(engine.UniqueSource, netbiosdomain)
			}
		}

		aos = append(aos, ao)
		ao.SetThreadsafe(false)
	}

	ld.dco = make(map[string]*engine.Objects) // Clear from memory

	return aos, nil
}
