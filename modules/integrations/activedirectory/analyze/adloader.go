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
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/pierrec/lz4/v4"
	"github.com/tinylib/msgp/msgp"
)

var (
	importcnf = analyze.Command.Flags().Bool("importcnf", false, "Import CNF (conflict) objects (experimental)")
	importdel = analyze.Command.Flags().Bool("importdel", false, "Import DEL (deleted) objects (experimental)")

	importhardened = analyze.Command.Flags().Bool("importhardened", false, "Import hardened objects (without objectclass attribute)")
	warnhardened   = analyze.Command.Flags().Bool("warnhardened", false, "Warn about hardened objects (without objectclass attribute)")

	limitattributes = analyze.Command.Flags().Bool("limitattributes", false, "Limit attributes to import (saves memory, experimental)")

	adsource = engine.AttributeValueString("Active Directory")
	Loader   = engine.AddLoader(func() engine.Loader { return (&ADLoader{}) })

	defaultNamingContext = engine.NewAttribute("defaultNamingContext")
)

type convertqueueitem struct {
	object *activedirectory.RawObject
	ao     *engine.Objects
}

type ADLoader struct {
	importmutex sync.Mutex
	done        sync.WaitGroup

	// Deduplicator for DNs that are somehow imported twice
	importeddns map[string]struct{}

	shardobjects map[string]*engine.Objects

	objectstoconvert chan convertqueueitem
	importcnf        bool // Import CNF (conflict) objects (experimental)
	importdel        bool // Import deleted objects (experimental)
	warnhardened     bool // Warn about hardened objects
	importhardened   bool // Import hardened objects
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
	ld.importdel = *importdel

	ld.warnhardened = *warnhardened
	ld.importhardened = *importhardened

	ld.importeddns = make(map[string]struct{})

	ld.shardobjects = make(map[string]*engine.Objects)
	ld.objectstoconvert = make(chan convertqueueitem, 8192)

	// AD Objects
	for i := 0; i < runtime.NumCPU(); i++ {
		ld.done.Add(1)
		go func() {
			// chunk := make([]*engine.Object, 0, 64)
			for item := range ld.objectstoconvert {
				if item.object.DistinguishedName == "" {
					if dnc, found := item.object.Attributes["defaultNamingContext"]; found {
						// There's a special place for people who do this
						item.object.DistinguishedName = "cn=RootDSE," + dnc[0]
						item.object.Attributes["objectClass"] = []string{"top", "rootdse"}
					} else {
						// We want the RootDSE KTHX, but ignore everything else
						ui.Warn().Msg("Empty DN, ignoring!")
						continue
					}
				}

				if category, found := item.object.Attributes["objectCategory"]; found && strings.HasPrefix(category[0], "CN=Foreign-Security-Principal") {
					// We don't want to import this
					// continue
				}

				// Convert
				o := item.object.ToObject(*limitattributes)

				if !ld.importcnf && strings.Contains(o.DN(), "\\0ACNF:") {
					continue // skip conflict object
				}

				if !ld.importdel && strings.Contains(o.DN(), "\\0ADEL:") {
					continue // skip deleted object
				}

				if !o.HasAttr(engine.ObjectClass) {
					if ld.warnhardened {
						if strings.Contains(o.DN(), ",CN=MicrosoftDNS,") {
							ui.Debug().Msgf("Hardened DNS object without objectclass detected: %v", o.DN())
						} else {
							ui.Warn().Msgf("Hardened object without objectclass detected: %v. This *might* affect your analysis, depending on object.", o.DN())
						}
					}
					if !ld.importhardened {
						continue
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
	ao = ld.shardobjects[lookupshard]
	if ao == nil {
		ao = engine.NewLoaderObjects(ld)
		// ao.AddDefaultFlex(engine.UniqueSource, engine.AttributeValueString(shard))
		ao.SetThreadsafe(true)
		ld.shardobjects[lookupshard] = ao
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
	for path, ao := range ld.shardobjects {
		var domainval engine.AttributeValues

		// Replace shard path value with the domain name the represents
		rootdse, found := ao.Find(engine.ObjectClass, engine.AttributeValueString("rootdse"))
		if found {
			domain := rootdse.OneAttrString(defaultNamingContext)
			domainval = engine.AttributeValueOne{Value: engine.AttributeValueString(domain)}
		} else {
			domaindns, found := ao.FindMulti(engine.ObjectClass, engine.AttributeValueString("domainDNS"))
			if !found {
				ui.Fatal().Msgf("Could not find RootDSE or domainDNS in '%v'", path)
			}
			for _, domain := range domaindns {
				if domain.HasAttr(engine.ObjectSid) {
					dn := domain.OneAttrString(engine.DistinguishedName)
					if domainval != nil {
						ui.Fatal().Msgf("Found multiple domainDNS in same path - please place each set of domain objects in their own subpath")
					}
					domainval = engine.AttributeValueOne{Value: engine.AttributeValueString(dn)}
				}
			}
			if domainval == nil {
				ui.Fatal().Msgf("Could not find domainDNS in object shard collection, giving up")
			}
		}

		// Indicate from which domain we saw this if we have the data
		if domainval != nil {
			for _, o := range ao.Slice() {
				o.Set(engine.UniqueSource, domainval)
			}
		}

		aos = append(aos, ao)
		ao.SetThreadsafe(false)
	}

	ld.shardobjects = make(map[string]*engine.Objects) // Clear from memory

	return aos, nil
}
