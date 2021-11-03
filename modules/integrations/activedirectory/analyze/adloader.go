package analyze

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/lkarlslund/adalanche/modules/analyze"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/pierrec/lz4/v4"
	"github.com/tinylib/msgp/msgp"
)

var (
	importall = analyze.Command.Flags().Bool("importall", false, "Load all attributes from dump (expands search options, but at the cost of memory")

	adsource = engine.AttributeValueString("Active Directory loader")

	Loader = engine.AddLoader(&ADLoader{})
)

type ADLoader struct {
	importmutex      sync.Mutex
	done             sync.WaitGroup
	ao               *engine.Objects
	objectstoconvert chan *activedirectory.RawObject
	domains          []domaininfo
	importall        bool
}

type domaininfo struct {
	suffix      string
	netbiosname string
}

func (ld *ADLoader) Name() string {
	return adsource.String()
}

func (ld *ADLoader) Init(ao *engine.Objects) error {
	ld.importall = *importall

	ld.ao = ao

	ld.objectstoconvert = make(chan *activedirectory.RawObject, 8192)

	for i := 0; i < runtime.NumCPU(); i++ {
		ld.done.Add(1)
		go func() {
			chunk := make([]*engine.Object, 0, 64)
			for addme := range ld.objectstoconvert {
				o := addme.ToObject(ld.importall)

				// Here's a quirky workaround that will bite me later
				// Legacy well known objects in ForeignSecurityPrincipals gives us trouble with duplicate SIDs - skip them
				if strings.Count(o.OneAttrString(engine.ObjectSid), "-") == 3 && strings.Contains(o.OneAttrString(engine.DistinguishedName), "CN=ForeignSecurityPrincipals") {
					continue
				}

				chunk = append(chunk, o)
				if cap(chunk) == len(chunk) {
					// Send chunk to objects
					ld.importmutex.Lock()
					ld.ao.Add(chunk...)
					ld.importmutex.Unlock()

					chunk = chunk[:0]
				}
			}
			// Process the last incomplete chunk
			ld.importmutex.Lock()
			ld.ao.Add(chunk...)
			ld.importmutex.Unlock()
			ld.done.Done()
		}()
	}

	return nil
}

func (ld *ADLoader) Load(path string, cb engine.ProgressCallbackFunc) error {
	if !strings.HasSuffix(path, ".objects.msgp.lz4") {
		return engine.ErrUninterested
	}

	// 	if ld.ao.Base == "" { // Shoot me, this is horrible
	// 	objs.Base = "dc=" + strings.Replace(domain, ".", ",dc=", -1)
	// 	objs.Domain = domain
	// 	domainparts := strings.Split(domain, ".") // From bad to worse FIXME
	// 	objs.DomainNetbios = strings.ToUpper(domainparts[0])
	// }

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
			ld.objectstoconvert <- &rawObject
		} else if msgp.Cause(err) == io.EOF {
			return nil
		} else {
			return fmt.Errorf("Problem decoding object: %v", err)
		}
	}
}

func (ld *ADLoader) Close() error {
	close(ld.objectstoconvert)
	ld.done.Wait()

	return nil
}
