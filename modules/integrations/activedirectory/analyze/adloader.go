package analyze

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	gsync "github.com/SaveTheRbtz/generic-sync-map-go"
	"github.com/lkarlslund/adalanche/modules/collection"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/frontend"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/pierrec/lz4/v4"
	"github.com/tinylib/msgp/msgp"
)

var (
	importcnf = frontend.Command.Flags().Bool("importcnf", false, "Import CNF (conflict) objects (experimental)")
	importdel = frontend.Command.Flags().Bool("importdel", false, "Import DEL (deleted) objects (experimental)")

	importhardened = frontend.Command.Flags().Bool("importhardened", false, "Import hardened objects (without objectclass attribute)")
	warnhardened   = frontend.Command.Flags().Bool("warnhardened", false, "Warn about hardened objects (without objectclass attribute)")

	limitattributes = frontend.Command.Flags().Bool("limitattributes", false, "Limit attributes to import (saves memory, experimental)")

	adsource = engine.NV("Active Directory")
	LoaderID = engine.AddLoader(func() engine.Loader { return (&ADLoader{}) })
	_        = engine.NewAttribute("defaultNamingContext")
)

type convertqueueitem struct {
	object *activedirectory.RawObject
	ao     *engine.IndexedGraph
}

type ADLoader struct {
	failed atomic.Uint64

	// Deduplicator for DNs that are somehow imported twice
	importeddns map[string]struct{}

	objectstoconvert chan convertqueueitem

	shardobjects gsync.MapOf[string, *engine.IndexedGraph]

	// Usernames that are enuerable using LDAP Nom nom or similar bruteforcers
	usernamesfiles []string

	done sync.WaitGroup

	importcnf      bool // Import CNF (conflict) objects (experimental)
	importdel      bool // Import deleted objects (experimental)
	warnhardened   bool // Warn about hardened objects
	importhardened bool // Import hardened objects
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

	ld.objectstoconvert = make(chan convertqueueitem, 8192)

	// AD Objects
	for i := 0; i < (runtime.NumCPU()+3)/4; i++ {
		ld.done.Add(1)
		go func() {
			// chunk := make(engine.ObjectSlice, 0, 64)
			for item := range ld.objectstoconvert {
				if item.object.DistinguishedName == "" {
					if dnc, found := item.object.Attributes["defaultNamingContext"]; found {
						// There's a special place for people who do this
						item.object.DistinguishedName = "cn=RootDSE," + dnc[0]
						item.object.Attributes["type"] = []string{"rootdse"}
					} else {
						// We want the RootDSE KTHX, but ignore everything else
						ui.Warn().Msg("Empty DN, ignoring!")
						continue
					}
				}

				// Convert
				o := item.object.ToObject(*limitattributes)

				if !ld.importcnf && strings.Contains(o.DN(), "\\0ACNF:") {
					continue // skip conflict object
				}

				if !ld.importdel && strings.Contains(o.DN(), "\\0ADEL:") {
					continue // skip deleted object
				}

				if strings.Contains(o.DN(), ",CN=ForeignSecurityPrincipals,DC=") { // FIXME also skip SYSTEM object
					continue // skip all foreign security principals
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

func (ld *ADLoader) getShard(path string) *engine.IndexedGraph {
	shard := filepath.Dir(path)

	new_ao := engine.NewLoaderObjects(ld)
	ao, _ := ld.shardobjects.LoadOrStore(shard, new_ao)
	return ao
}

func (ld *ADLoader) Load(path string, cb engine.ProgressCallbackFunc) (resultErr error) {
	defer func() {
		if resultErr != nil && resultErr != engine.ErrUninterested {
			ld.failed.Add(1)
		}
	}()
	if strings.HasSuffix(path, collection.ADSuffix) {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		// Preflight before admitting any records to the shared analysis shard.
		verified, err := collection.NewReader(f, collection.AD)
		if err != nil {
			return err
		}
		err = activedirectory.ValidateObjects(&activedirectory.ObjectReader{Container: verified})
		verified.Close()
		if err != nil {
			return err
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		r, err := collection.NewReader(f, collection.AD)
		if err != nil {
			return err
		}
		defer r.Close()
		objects := activedirectory.ObjectReader{Container: r}
		ao := ld.getShard(path)
		for {
			object, err := objects.Next()
			if err == io.EOF {
				if r.Completion.Outcome != "complete" {
					ui.Warn().Msgf("AD collection acquisition status: %s", r.Completion.Outcome)
				}
				return nil
			}
			if err != nil {
				return err
			}
			ld.objectstoconvert <- convertqueueitem{object, ao}
		}
	}
	if strings.HasSuffix(path, ".objects.msgp.lz4") {
		ao := ld.getShard(path)

		cachefile, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("problem opening domain cache file: %v", err)
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
				return fmt.Errorf("problem decoding object: %v", err)
			}
		}
	} else if strings.HasSuffix(path, ".usernames.txt") {
		ld.usernamesfiles = append(ld.usernamesfiles, path)
	}
	return engine.ErrUninterested
}

func (ld *ADLoader) Close() ([]*engine.IndexedGraph, error) {
	close(ld.objectstoconvert)
	ld.done.Wait()

	var aos []*engine.IndexedGraph
	if failures := ld.failed.Load(); failures != 0 {
		ld.shardobjects.Range(func(_ string, ao *engine.IndexedGraph) bool { aos = append(aos, ao); return true })
		return aos, fmt.Errorf("%d AD collections failed to import", failures)
	}
	ld.shardobjects.Range(func(path string, ao *engine.IndexedGraph) bool {
		_, netbiosname, _, _, err := FindDomain(ao)
		if err != nil {
			ui.Fatal().Msgf("Can't apply unique source for AD data from %v, this will give errors during object merging: %v", path, err)
		} else {
			// Indicate from which domain we saw this if we have the data
			nb := engine.NV(netbiosname)
			ao.IterateStable(func(o *engine.Node) bool {
				o.SetFlex(engine.DataSource, nb)
				return true
			})
		}

		aos = append(aos, ao)
		return true // next
	})

	if len(aos) > 0 && len(ld.usernamesfiles) > 0 {
		// Add special object to find the files later
		var v engine.AttributeValues
		for _, uf := range ld.usernamesfiles {
			v = append(v, engine.NV(uf))
		}
		aos[0].AddNew(
			engine.Name, engine.NV("$$USERNAMEFILES$$"),
			engine.A("files"), v,
		)
	}

	return aos, nil
}
