package engine

import (
	"strings"
	"sync"

	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"github.com/rs/zerolog/log"
)

var idcounter uint32 // Unique ID +1 to assign to Object added to this collection if it's zero

type typestatistics [256]int

type Objects struct {
	threadsafemutex sync.RWMutex
	DefaultValues   []interface{}
	root            *Object
	idindex         map[uint32]*Object
	uniqueindex     map[Attribute]map[interface{}]*Object
	multiindex      map[Attribute]map[interface{}][]*Object
	asarray         []*Object
	typecount       typestatistics
	threadsafe      int
}

func (os *Objects) Init() {
	os.uniqueindex = make(map[Attribute]map[interface{}]*Object)
	os.multiindex = make(map[Attribute]map[interface{}][]*Object)
	os.idindex = make(map[uint32]*Object)
}

func (os *Objects) AddDefaultFlex(data ...interface{}) {
	os.DefaultValues = append(os.DefaultValues, data...)
}

func (os *Objects) SetThreadsafe(enable bool) {
	if enable {
		os.threadsafe++
	} else {
		os.threadsafe--
	}
	if os.threadsafe < 0 {
		panic("threadsafe is negative")
	}
	setThreadsafe(enable) // Do this globally for individial objects too
}

func (os *Objects) lock() {
	if os.threadsafe != 0 {
		os.threadsafemutex.Lock()
	}
}

func (os *Objects) rlock() {
	if os.threadsafe != 0 {
		os.threadsafemutex.RLock()
	}
}

func (os *Objects) unlock() {
	if os.threadsafe != 0 {
		os.threadsafemutex.Unlock()
	}
}

func (os *Objects) runlock() {
	if os.threadsafe != 0 {
		os.threadsafemutex.RUnlock()
	}
}

func (os *Objects) addIndex(attribute Attribute) {
	// create index
	if attribute.IsNonUnique() {
		os.multiindex[attribute] = make(map[interface{}][]*Object)
	} else {
		os.uniqueindex[attribute] = make(map[interface{}]*Object)
	}

	// add all existing stuff to index
	for _, o := range os.asarray {
		value := o.OneAttr(attribute)
		if value != nil {
			var key interface{}
			// If it's a string, lowercase it before adding to index, we do the same on lookups
			if vs, ok := value.(AttributeValueString); ok {
				key = strings.ToLower(string(vs))
			} else {
				key = value.Raw()
			}

			// Add to index
			if attribute.IsNonUnique() {
				os.multiindex[attribute][key] = append(os.multiindex[attribute][key], o)
			} else {
				os.uniqueindex[attribute][key] = o
			}
		}
	}
}

func (os *Objects) SetRoot(ro *Object) {
	os.root = ro
}

func (os *Objects) DropIndexes() {
	// Clear all indexes
	os.lock()
	defer os.unlock()
	os.uniqueindex = make(map[Attribute]map[interface{}]*Object)
	os.multiindex = make(map[Attribute]map[interface{}][]*Object)
}

// Force reindex after changing data in Objects
func (os *Objects) Reindex() {
	// Clear all indexes
	os.lock()
	defer os.unlock()
	for a := range os.uniqueindex {
		os.uniqueindex[a] = make(map[interface{}]*Object)
	}
	for a := range os.multiindex {
		os.multiindex[a] = make(map[interface{}][]*Object)
	}
	// Put all objects in index
	for _, o := range os.asarray {
		os.updateIndex(o, false)
	}
}

func (os *Objects) ReindexObject(o *Object) {
	os.lock()
	os.updateIndex(o, true)
	os.unlock()
}

func (os *Objects) updateIndex(o *Object, warn bool) {
	for attribute := range os.uniqueindex {
		values := o.Attr(attribute)
		if values.Len() > 1 && !attributenums[attribute].multi {
			log.Warn().Msgf("Encountered multiple values on attribute %v, but is not declared as multival", attribute.String())
			log.Debug().Msgf("Object dump:\n%s", o.String(os))
		}
		for _, value := range values.Slice() {
			// If it's a string, lowercase it before adding to index, we do the same on lookups
			if vs, ok := value.(AttributeValueString); ok {
				value = AttributeValueString(strings.ToLower(string(vs)))
			}
			if warn {
				existing, dupe := os.uniqueindex[attribute][value.Raw()]
				if dupe && existing != o {
					log.Warn().Msgf("Duplicate index %v value %v when trying to add %v, already exists as %v, index still points to original object", attribute.String(), value.String(), o.Label(), existing.Label())
					log.Debug().Msgf("NEW: %v", o.StringNoACL())
					log.Debug().Msgf("EXISTING: %v", existing.StringNoACL())
					continue
				}
			}
			os.uniqueindex[attribute][value.Raw()] = o
		}
	}

	for attribute := range os.multiindex {
		values := o.Attr(attribute)
		if values.Len() > 1 && !attributenums[attribute].multi {
			log.Warn().Msgf("Encountered multiple values on attribute %v, but is not declared as multival", attribute.String())
			log.Debug().Msgf("Object dump:\n%s", o.String(os))
		}
		for _, value := range values.Slice() {
			// If it's a string, lowercase it before adding to index, we do the same on lookups
			if vs, ok := value.(AttributeValueString); ok {
				value = AttributeValueString(strings.ToLower(string(vs)))
			}
			os.multiindex[attribute][value.Raw()] = append(os.multiindex[attribute][value.Raw()], o)
		}
	}
}

func (os *Objects) Filter(evaluate func(o *Object) bool) *Objects {
	var result Objects
	result.Init()

	os.rlock()
	objects := os.asarray
	os.runlock()
	for _, object := range objects {
		if evaluate(object) {
			result.Add(object)
		}
	}
	return &result
}

func (os *Objects) AddMerge(attrtomerge []Attribute, obs ...*Object) {
	os.lock()
	os.addmerge(attrtomerge, obs...)
	os.unlock()
}

func (os *Objects) AddNew(flexinit ...interface{}) *Object {
	o := NewObject(flexinit...)
	if os.DefaultValues != nil {
		o.SetFlex(os.DefaultValues...)
	}
	os.lock()
	os.addmerge(nil, o)
	os.unlock()
	return o
}

func (os *Objects) Add(obs ...*Object) {
	os.lock()
	os.addmerge(nil, obs...)
	os.unlock()
}

func (os *Objects) addmerge(attrtomerge []Attribute, obs ...*Object) {
	for _, o := range obs {
		if !os.merge(attrtomerge, o) {
			os.add(o)
		}
	}
}

// Attemps to merge the object into the objects
func (os *Objects) Merge(attrtomerge []Attribute, o *Object) bool {
	os.lock()
	result := os.merge(attrtomerge, o)
	os.unlock()
	return result
}

func (os *Objects) merge(attrtomerge []Attribute, o *Object) bool {
	if len(attrtomerge) > 0 {
		for _, mergeattr := range attrtomerge {
			for _, lookfor := range o.Attr(mergeattr).Slice() {
				if lookfor == nil {
					continue
				}
				if mergetargets, found := os.FindMulti(mergeattr, lookfor); found {

				targetloop:
					for _, mergetarget := range mergetargets {
						for _, mf := range mergeapprovers {
							if mf != nil {
								res, err := mf(o, mergetarget)
								switch err {
								case ErrDontMerge:
									continue targetloop
								case ErrMergeOnThis, nil:
									// Let the code below do the merge
								default:
									log.Fatal().Msgf("Error merging %v: %v", o.Label(), err)
								}
								if res != nil {
									// Custom merge - how do we handle this?
									log.Fatal().Msgf("Custom merge function not supported yet")
									return false
								}
							}
						}
						log.Trace().Msgf("Merging %v with %v on attribute %v", o.Label(), mergetarget.Label(), mergeattr.String())
						mergetarget.Absorb(o)
						os.updateIndex(mergetarget, false)
						return true
					}
				}
			}
		}
	}
	return false
}

func (os *Objects) add(o *Object) {
	// Add this to the iterator array
	if os.DefaultValues != nil {
		o.SetFlex(os.DefaultValues...)
	}

	// Do chunked extensions for speed
	if len(os.asarray) == cap(os.asarray) {
		newarray := make([]*Object, len(os.asarray), len(os.asarray)+1024)
		copy(newarray, os.asarray)
		os.asarray = newarray
	}

	if _, found := os.idindex[o.ID()]; found {
		panic("Tried to add same object twice")
	}

	os.asarray = append(os.asarray, o)

	os.idindex[o.ID()] = o

	os.updateIndex(o, true)

	// Statistics
	os.typecount[o.Type()]++
}

// First object added is the root object
func (os *Objects) Root() *Object {
	return os.root
}

func (os *Objects) Statistics() typestatistics {
	os.rlock()
	defer os.runlock()
	return os.typecount
}

func (os *Objects) Slice() []*Object {
	os.rlock()
	defer os.runlock()
	return os.asarray
}

func (os *Objects) Len() int {
	os.rlock()
	defer os.runlock()
	return len(os.asarray)
}

func (os *Objects) FindByID(id uint32) (o *Object, found bool) {
	os.rlock()
	o, found = os.idindex[id]
	os.runlock()
	return
}

func (os *Objects) MergeOrAdd(attribute Attribute, value AttributeValue, flexinit ...interface{}) (o *Object, found bool) {
	os.lock()
	defer os.unlock()
	if o, found := os.find(attribute, value); found {
		flexinit = append(flexinit, attribute, value)
		eatme := NewObject(flexinit...)
		// Use the first one found
		o[0].Absorb(eatme)
		return o[0], true
	}
	no := NewObject(append(flexinit, attribute, value)...)
	os.addmerge(nil, no)
	return no, false
}

func (os *Objects) FindOrAdd(attribute Attribute, value AttributeValue, flexinit ...interface{}) (o *Object, found bool) {
	os.lock()
	defer os.unlock()
	if o, found := os.find(attribute, value); found {
		// Use the first one found
		return o[0], true
	}
	no := NewObject(append(flexinit, attribute, value)...)
	os.addmerge(nil, no)
	return no, false
}

func (os *Objects) Find(attribute Attribute, value AttributeValue) (o *Object, found bool) {
	os.lock()
	defer os.unlock()
	v, found := os.find(attribute, value)
	if len(v) != 1 {
		return nil, false
	}
	return v[0], found
}

func (os *Objects) FindMulti(attribute Attribute, value AttributeValue) (o []*Object, found bool) {
	os.lock()
	defer os.unlock()
	return os.find(attribute, value)
}

func (os *Objects) find(attribute Attribute, value AttributeValue) ([]*Object, bool) {
	var lookup interface{}

	// If it's a string, lowercase it before adding to index, we do the same on lookups
	if vs, ok := value.(AttributeValueString); ok {
		lookup = strings.ToLower(string(vs))
	} else {
		lookup = value.Raw()
	}

	if attribute.IsNonUnique() {
		index, found := os.multiindex[attribute]
		if !found {
			os.addIndex(attribute)
			index = os.multiindex[attribute]
		}
		result, found := index[lookup]
		return result, found
	}

	index, found := os.uniqueindex[attribute]
	if !found {
		os.addIndex(attribute)
		index = os.uniqueindex[attribute]
	}
	result, found := index[lookup]
	return []*Object{result}, found
}

func (os *Objects) DistinguishedParent(o *Object) (*Object, bool) {
	var dn = o.DN()
	for {
		firstcomma := strings.Index(dn, ",")
		if firstcomma == -1 {
			return nil, false // At the top
		}
		if firstcomma > 0 {
			if dn[firstcomma-1] == '\\' {
				// False alarm, strip it an go on
				dn = dn[firstcomma+1:]
				continue
			}
		}
		dn = dn[firstcomma+1:]
		break
	}

	// Use object chaining if possible
	directparent := o.Parent()
	if directparent != nil && directparent.OneAttrString(DistinguishedName) == dn {
		return directparent, true
	}

	return os.Find(DistinguishedName, AttributeValueString(dn))
}

func (os *Objects) Subordinates(o *Object) *Objects {
	return os.Filter(func(o2 *Object) bool {
		candidatedn := o2.DN()
		mustbesubordinateofdn := o.DN()
		if len(candidatedn) <= len(mustbesubordinateofdn) {
			return false
		}
		if !strings.HasSuffix(o2.DN(), o.DN()) {
			return false
		}
		prefixlength := len(candidatedn) - len(mustbesubordinateofdn)
		escapedcommas := strings.Count(candidatedn[:prefixlength], "\\,")
		commas := strings.Count(candidatedn[:prefixlength], ",")
		return commas-escapedcommas == 1
	})
}

func (os *Objects) FindOrAddSID(s windowssecurity.SID) *Object {
	os.lock()
	defer os.unlock()
	o, found := os.find(ObjectSid, AttributeValueSID(s))
	if found {
		// Use the first one found
		return o[0]
	}

	no := NewObject(
		ObjectSid, AttributeValueSID(s),
	)
	if os.DefaultValues != nil {
		no.SetFlex(os.DefaultValues...)
	}

	os.addmerge(nil, no)
	return no
}

func (os *Objects) FindGUID(g uuid.UUID) (o *Object, found bool) {
	return os.Find(ObjectGUID, AttributeValueGUID(g))
}
