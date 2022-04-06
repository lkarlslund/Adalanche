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
	root            *Object
	asarray         []*Object
	DefaultValues   []interface{}
	idindex         map[uint32]*Object
	uniqueindex     map[Attribute]map[interface{}]*Object
	multiindex      map[Attribute]map[interface{}]map[*Object]struct{}
	threadsafemutex sync.RWMutex
	typecount       typestatistics
	threadsafe      int
}

func NewObjects() *Objects {
	var os Objects
	os.uniqueindex = make(map[Attribute]map[interface{}]*Object)
	os.multiindex = make(map[Attribute]map[interface{}]map[*Object]struct{})
	os.idindex = make(map[uint32]*Object)
	return &os
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

func (os *Objects) AddIndex(attribute Attribute) {
	os.lock()
	os.addIndex(attribute)
	os.unlock()
}

func (os *Objects) GetIndex(attribute Attribute) map[interface{}][]*Object {
	os.rlock()
	defer os.runlock()
	if attribute.IsNonUnique() {
		i := os.multiindex[attribute]
		mi := make(map[interface{}][]*Object)
		for k, v := range i {
			s := make([]*Object, len(v))
			i := 0
			for o, _ := range v {
				s[i] = o
				i++
			}
			mi[k] = s
		}
		return mi
	}

	i := os.uniqueindex[attribute]
	mi := make(map[interface{}][]*Object)
	for k, v := range i {
		mi[k] = []*Object{v}
	}
	return mi
}

func (os *Objects) addIndex(attribute Attribute) {
	// create index
	if attribute.IsNonUnique() {
		os.multiindex[attribute] = make(map[interface{}]map[*Object]struct{})
	} else {
		os.uniqueindex[attribute] = make(map[interface{}]*Object)
	}

	// add all existing stuff to index
	for _, o := range os.asarray {
		for _, value := range o.Attr(attribute).Slice() {
			key := attributeValueToIndex(value)

			// Add to index
			if attribute.IsNonUnique() {
				if os.multiindex[attribute][key] == nil {
					os.multiindex[attribute][key] = make(map[*Object]struct{})
				}
				os.multiindex[attribute][key][o] = struct{}{}
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
	os.multiindex = make(map[Attribute]map[interface{}]map[*Object]struct{})
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
		os.multiindex[a] = make(map[interface{}]map[*Object]struct{})
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
		for _, value := range o.Attr(attribute).Slice() {
			// If it's a string, lowercase it before adding to index, we do the same on lookups
			indexval := attributeValueToIndex(value)
			if warn {
				existing, dupe := os.uniqueindex[attribute][indexval]
				if dupe && existing != o {
					log.Warn().Msgf("Duplicate index %v value %v when trying to add %v, already exists as %v, index still points to original object", attribute.String(), value.String(), o.Label(), existing.Label())
					log.Debug().Msgf("NEW DN: %v", o.DN())
					log.Debug().Msgf("EXISTING DN: %v", existing.DN())
					continue
				}
			}
			os.uniqueindex[attribute][indexval] = o
		}
	}

	for attribute := range os.multiindex {
		values := o.Attr(attribute)
		for _, value := range values.Slice() {
			indexval := attributeValueToIndex(value)
			// If it's a string, lowercase it before adding to index, we do the same on lookups

			if os.multiindex[attribute][indexval] == nil {
				os.multiindex[attribute][indexval] = make(map[*Object]struct{})
			}

			os.multiindex[attribute][indexval][o] = struct{}{}
		}
	}
}

func attributeValueToIndex(value AttributeValue) interface{} {
	if vs, ok := value.(AttributeValueString); ok {
		return strings.ToLower(string(vs))
	}
	return value.Raw()
}

func (os *Objects) Filter(evaluate func(o *Object) bool) *Objects {
	result := NewObjects()

	os.rlock()
	objects := os.asarray
	os.runlock()
	for _, object := range objects {
		if evaluate(object) {
			result.Add(object)
		}
	}
	return result
}

func (os *Objects) AddMerge(attrtomerge []Attribute, obs ...*Object) {
	os.lock()
	os.addmerge(attrtomerge, obs...)
	os.unlock()
}

func (os *Objects) AddNew(flexinit ...interface{}) *Object {
	o := NewObject(flexinit...)
	if os.DefaultValues != nil {
		o.setFlex(os.DefaultValues...)
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
	result := os.merge(attrtomerge, o)
	return result
}

func (os *Objects) merge(attrtomerge []Attribute, o *Object) bool {
	// var deb int
	if len(attrtomerge) > 0 {
		for _, mergeattr := range attrtomerge {
			if !o.HasAttr(mergeattr) {
				continue
			}
			for _, lookfor := range o.Attr(mergeattr).Slice() {
				if mergetargets, found := os.FindMulti(mergeattr, lookfor); found {
				targetloop:
					for _, mergetarget := range mergetargets {
						for attr, values := range o.AttributeValueMap() {
							if attr.IsSingle() && mergetarget.HasAttr(attr) {
								if !CompareAttributeValues(values.Slice()[0], mergetarget.Attr(attr).Slice()[0]) {
									// Conflicting attribute values, we can't merge these
									log.Debug().Msgf("Not merging %v into %v on %v with value '%v', as attribute %v is different", o.Label(), mergetarget.Label(), mergeattr.String(), lookfor.String(), attr.String())
									// if attr == WhenCreated {
									// 	log.Debug().Msgf("Object details: %v", o.StringNoACL())
									// 	log.Debug().Msgf("Mergetarget details: %v", mergetarget.StringNoACL())
									// }
									continue targetloop
								}
							}
						}
						for _, mfi := range mergeapprovers {
							res, err := mfi.mergefunc(o, mergetarget)
							switch err {
							case ErrDontMerge:
								// if !strings.HasPrefix(mfi.name, "QUIET") {
								// 	log.Debug().Msgf("Not merging %v with %v on %v, because %v said so", o.Label(), mergetarget.Label(), mergeattr.String(), mfi.name)
								// }
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
						// log.Trace().Msgf("Merging %v with %v on attribute %v", o.Label(), mergetarget.Label(), mergeattr.String())
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
		o.setFlex(os.DefaultValues...)
	}

	// Do chunked extensions for speed
	if len(os.asarray) == cap(os.asarray) {
		increase := len(os.asarray) / 8
		if increase < 1024 {
			increase = 1024
		}
		newarray := make([]*Object, len(os.asarray), len(os.asarray)+increase)
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

func (os *Objects) FindTwo(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue) (o *Object, found bool) {
	results, found := os.FindTwoMulti(attribute, value, attribute2, value2)
	if !found {
		return nil, false
	}
	return results[0], len(results) == 1
}

func (os *Objects) FindTwoMulti(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue) (o []*Object, found bool) {
	os.lock()
	defer os.unlock()
	v, found := os.find(attribute, value)
	if !found {
		return nil, false
	}
	v2, found := os.find(attribute2, value2)
	if !found {
		return nil, false
	}
	var results []*Object
	for _, o := range v {
		for _, o2 := range v2 {
			if o == o2 {
				results = append(results, o)
			}
		}
	}
	return results, len(results) > 0
}

func (os *Objects) find(attribute Attribute, value AttributeValue) ([]*Object, bool) {
	// If it's a string, lowercase it before adding to index, we do the same on lookups
	lookup := attributeValueToIndex(value)

	if attribute.IsNonUnique() {
		index, found := os.multiindex[attribute]
		if !found {
			os.addIndex(attribute)
			index = os.multiindex[attribute]
		}
		result, found := index[lookup]
		s := make([]*Object, len(result))
		i := 0
		for o, _ := range result {
			s[i] = o
			i++
		}
		return s, found
	}

	index, found := os.uniqueindex[attribute]
	if !found {
		os.addIndex(attribute)
		index = os.uniqueindex[attribute]
	}

	result, found := index[lookup]
	if !found {
		return nil, false
	}
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
	if directparent != nil && strings.EqualFold(directparent.OneAttrString(DistinguishedName), dn) {
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
