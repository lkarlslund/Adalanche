package engine

import (
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/akyoto/cache"
	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

var idcounter uint32 // Unique ID +1 to assign to Object added to this collection if it's zero

type typestatistics [256]int

type Objects struct {
	root          *Object
	DefaultValues []interface{}

	objectmutex sync.RWMutex

	asarray []*Object // All objects in this collection, returned by .Slice()
	asmap   map[*Object]struct{}

	indexlock sync.RWMutex

	indexes      []*Index
	multiindexes map[uint32]*Index // Indexes for multiple attributes (lower attr < 16 || higher attr)

	idindex map[uint32]int // Offset into asarray

	typecount typestatistics
}

type Index struct {
	lookup map[interface{}][]*Object
	sync.RWMutex
}

func (i *Index) Init() {
	i.lookup = make(map[interface{}][]*Object)
}

func (i *Index) Lookup(key interface{}) ([]*Object, bool) {
	i.RLock()
	results, found := i.lookup[key]
	i.RUnlock()
	return results, found
}

func (i *Index) Add(key interface{}, o *Object, undupe bool) {
	i.Lock()
	if undupe {
		existing := i.lookup[key]
		for _, dupe := range existing {
			if dupe == o {
				i.Unlock()
				return
			}
		}
	}
	i.lookup[key] = append(i.lookup[key], o)
	i.Unlock()
}

// Expensive, it's a map copy!
func (i *Index) AsMap() map[interface{}][]*Object {
	i.RLock()
	m := make(map[interface{}][]*Object)
	for k, v := range i.lookup {
		s := make([]*Object, len(v), len(v))
		copy(s, v)
		m[k] = s
	}
	i.RUnlock()
	return m
}

func NewObjects() *Objects {
	var os Objects
	os.idindex = make(map[uint32]int)
	os.asmap = make(map[*Object]struct{})
	os.multiindexes = make(map[uint32]*Index)
	return &os
}

func (os *Objects) AddDefaultFlex(data ...interface{}) {
	os.DefaultValues = append(os.DefaultValues, data...)
}

func (os *Objects) GetIndex(attribute Attribute) *Index {
	os.indexlock.RLock()

	// No room for index for this attribute
	if len(os.indexes) <= int(attribute) {
		os.indexlock.RUnlock()
		os.indexlock.Lock()
		// Someone might have beaten us to it?
		if len(os.indexes) <= int(attribute) {
			newindexes := make([]*Index, attribute+1, attribute+1)
			copy(newindexes, os.indexes)
			os.indexes = newindexes
		}
		os.indexlock.Unlock()

		os.indexlock.RLock()
	}

	index := os.indexes[attribute]

	// No index for this attribute
	if index == nil {
		os.indexlock.RUnlock()

		os.indexlock.Lock()
		// Someone might have beaten us to it
		index = os.indexes[attribute]
		if index == nil {
			index = &Index{}

			// Initialize index and add existing stuff
			os.refreshIndex(attribute, index)

			os.indexes[attribute] = index
		}
		os.indexlock.Unlock()
		return index
	}

	os.indexlock.RUnlock()
	return index

	/*
		i := os.indexes[attribute]
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
		return mi */
}

func (os *Objects) GetMultiIndex(attribute, attribute2 Attribute) *Index {
	// Consistently map to the right index no matter what order they are called
	if attribute < attribute2 {
		attribute, attribute2 = attribute2, attribute
	}

	if attribute2 == NonExistingAttribute {
		panic("Cannot create multi-index with non-existing attribute")
	}

	os.indexlock.RLock()

	// No room for index for this attribute
	indexkey := uint32(attribute)<<16 | uint32(attribute2)

	index, found := os.multiindexes[indexkey]
	if found {
		os.indexlock.RUnlock()
		return index
	}

	os.indexlock.RUnlock()
	os.indexlock.Lock()

	index, found = os.multiindexes[indexkey]
	if found {
		// Someone beat us to it
		os.indexlock.Unlock()
		return index
	}

	index = &Index{}

	// Initialize index and add existing stuff
	os.refreshMultiIndex(attribute, attribute2, index)

	os.multiindexes[indexkey] = index

	os.indexlock.Unlock()

	return index
}

func (os *Objects) refreshIndex(attribute Attribute, index *Index) {
	index.Init()

	// add all existing stuff to index
	for _, o := range os.asarray {
		o.Attr(attribute).Iterate(func(value AttributeValue) bool {
			key := AttributeValueToIndex(value)

			// Add to index
			index.Add(key, o, false)

			return true // continue
		})
	}
}

type multiindexkey struct {
	value1 interface{}
	value2 interface{}
}

func (os *Objects) refreshMultiIndex(attribute, attribute2 Attribute, index *Index) {
	index.Init()

	// add all existing stuff to index
	for _, o := range os.asarray {
		if !o.HasAttr(attribute) || !o.HasAttr(attribute2) {
			continue
		}

		o.Attr(attribute).Iterate(func(value AttributeValue) bool {
			key := AttributeValueToIndex(value)
			o.Attr(attribute2).Iterate(func(value2 AttributeValue) bool {
				key2 := AttributeValueToIndex(value2)

				// Add to index
				index.Add(multiindexkey{key, key2}, o, false)

				return true
			})
			return true
		})
	}
}

func (os *Objects) SetRoot(ro *Object) {
	os.root = ro
}

func (os *Objects) DropIndexes() {
	// Clear all indexes
	os.indexlock.Lock()
	os.indexes = make([]*Index, 0)
	os.multiindexes = make(map[uint32]*Index)
	os.indexlock.Unlock()
}

func (os *Objects) DropIndex(attribute Attribute) {
	// Clear all indexes
	os.indexlock.Lock()
	if len(os.indexes) > int(attribute) {
		os.indexes[attribute] = nil
	}
	os.indexlock.Unlock()
}

func (os *Objects) ReindexObject(o *Object, isnew bool) {
	os.indexlock.RLock()

	// Single attribute indexes
	for i, index := range os.indexes {
		attribute := Attribute(i)
		if index != nil {
			o.AttrRendered(attribute).Iterate(func(value AttributeValue) bool {
				// If it's a string, lowercase it before adding to index, we do the same on lookups
				indexval := AttributeValueToIndex(value)

				unique := attribute.IsUnique()

				if isnew && unique {
					existing, dupe := index.Lookup(indexval)
					if dupe && existing[0] != o {
						ui.Warn().Msgf("Duplicate index %v value %v when trying to add %v, already exists as %v, index still points to original object", attribute.String(), value.String(), o.Label(), existing[0].Label())
						ui.Debug().Msgf("NEW DN: %v", o.DN())
						ui.Debug().Msgf("EXISTING DN: %v", existing[0].DN())
						return true
					}
				}

				index.Add(indexval, o, !isnew)
				return true
			})
		}
	}

	// Multi indexes
	for i, index := range os.multiindexes {
		attribute := Attribute((i >> 16) & 0xffff)
		attribute2 := Attribute(i & 0xffff)

		if !o.HasAttr(attribute) || !o.HasAttr(attribute2) {
			continue
		}

		o.Attr(attribute).Iterate(func(value AttributeValue) bool {
			key := AttributeValueToIndex(value)
			o.Attr(attribute2).Iterate(func(value2 AttributeValue) bool {
				key2 := AttributeValueToIndex(value2)

				index.Add(multiindexkey{key, key2}, o, !isnew)

				return true
			})
			return true
		})
	}
	os.indexlock.RUnlock()
}

var avtiCache = cache.New(time.Second * 30)

func AttributeValueToIndex(value AttributeValue) interface{} {
	if vs, ok := value.(AttributeValueString); ok {
		s := string(vs)
		if lowered, found := avtiCache.Get(s); found {
			return lowered
		}
		lowered := strings.ToLower(string(vs))
		avtiCache.Set(s, lowered, time.Second*30)
		return lowered
	}
	return value.Raw()
}

func (os *Objects) Filter(evaluate func(o *Object) bool) *Objects {
	result := NewObjects()

	os.objectmutex.RLock()
	objects := os.asarray
	for _, object := range objects {
		if evaluate(object) {
			result.Add(object)
		}
	}
	os.objectmutex.RUnlock()
	return result
}

func (os *Objects) AddNew(flexinit ...interface{}) *Object {
	o := NewObject(flexinit...)
	if os.DefaultValues != nil {
		o.setFlex(os.DefaultValues...)
	}
	os.AddMerge(nil, o)
	return o
}

func (os *Objects) Add(obs ...*Object) {
	os.AddMerge(nil, obs...)
}

func (os *Objects) AddMerge(attrtomerge []Attribute, obs ...*Object) {
	for _, o := range obs {
		if !os.Merge(attrtomerge, o) {
			os.objectmutex.Lock()
			os.add(o)
			os.objectmutex.Unlock()
		}
	}
}

// Attemps to merge the object into the objects
func (os *Objects) Merge(attrtomerge []Attribute, o *Object) bool {
	os.objectmutex.RLock()
	if _, found := os.asmap[o]; found {
		ui.Fatal().Msg("Object already exists in objects, so we can't merge it")
	}
	os.objectmutex.RUnlock()

	// var deb int
	var merged bool
	if len(attrtomerge) > 0 {
		for _, mergeattr := range attrtomerge {
			o.Attr(mergeattr).Iterate(func(lookfor AttributeValue) bool {
				if mergetargets, found := os.FindMulti(mergeattr, lookfor); found {
				targetloop:
					for _, mergetarget := range mergetargets {
						var failed bool
						o.AttrIterator(func(attr Attribute, values AttributeValues) bool {
							if attr.IsSingle() && mergetarget.HasAttr(attr) {
								if !CompareAttributeValues(values.First(), mergetarget.Attr(attr).First()) {
									// Conflicting attribute values, we can't merge these
									ui.Trace().Msgf("Not merging %v into %v on %v with value '%v', as attribute %v is different (%v != %v)", o.Label(), mergetarget.Label(), mergeattr.String(), lookfor.String(), attr.String(), values.First().String(), mergetarget.Attr(attr).First().String())
									failed = true
									return false
								}
							}
							return true
						})
						if failed {
							continue targetloop
						}
						for _, mfi := range mergeapprovers {
							res, err := mfi.mergefunc(o, mergetarget)
							switch err {
							case ErrDontMerge:
								// if !strings.HasPrefix(mfi.name, "QUIET") {
								// 	ui.Debug().Msgf("Not merging %v with %v on %v, because %v said so", o.Label(), mergetarget.Label(), mergeattr.String(), mfi.name)
								// }

								continue targetloop
							case ErrMergeOnThis, nil:
								// Let the code below do the merge
							default:
								ui.Fatal().Msgf("Error merging %v: %v", o.Label(), err)
							}
							if res != nil {
								// Custom merge - how do we handle this?
								ui.Fatal().Msgf("Custom merge function not supported yet")
							}
						}
						// ui.Trace().Msgf("Merging %v with %v on attribute %v", o.Label(), mergetarget.Label(), mergeattr.String())

						mergetarget.Absorb(o)
						os.ReindexObject(mergetarget, false)
						merged = true
						return false
					}
				}
				return true
			})
			if merged {
				break
			}
		}
	}
	return merged
}

func (os *Objects) add(o *Object) {
	if o.id == 0 {
		ui.Fatal().Msg("Objects must have a unique ID")
	}

	if _, found := os.asmap[o]; found {
		ui.Fatal().Msg("Object already exists in objects, so we can't add it")
	}

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

	// Add this to the iterator array and indexes
	os.asarray = append(os.asarray, o)
	os.idindex[o.ID()] = len(os.asarray) - 1
	os.asmap[o] = struct{}{}

	os.ReindexObject(o, true)

	// Statistics
	os.typecount[o.Type()]++
}

// First object added is the root object
func (os *Objects) Root() *Object {
	return os.root
}

func (os *Objects) Statistics() typestatistics {
	os.objectmutex.RLock()
	defer os.objectmutex.RUnlock()
	return os.typecount
}

func (os *Objects) Slice() []*Object {
	os.objectmutex.RLock()
	defer os.objectmutex.RUnlock()
	return os.asarray
}

func (os *Objects) Len() int {
	os.objectmutex.RLock()
	defer os.objectmutex.RUnlock()
	return len(os.asarray)
}

func (os *Objects) Iterate(each func(o *Object) bool) {
	for _, o := range os.asarray {
		if !each(o) {
			break
		}
	}
}

func (os *Objects) IterateParallel(each func(o *Object) bool, parallelFuncs int) {
	if parallelFuncs == 0 {
		parallelFuncs = runtime.NumCPU()
	}
	queue := make(chan *Object, parallelFuncs*2)
	var wg sync.WaitGroup

	var stop atomic.Bool

	for i := 0; i < parallelFuncs; i++ {
		wg.Add(1)
		go func() {
			for o := range queue {
				if !each(o) {
					stop.Store(false)
				}
			}
			wg.Done()
		}()
	}

	for i, o := range os.asarray {
		if i&0x400 == 0 && stop.Load() {
			ui.Debug().Msg("Aborting parallel iterator for Objects")
			break
		}
		queue <- o
	}

	close(queue)
	wg.Wait()
}

func (os *Objects) FindByID(id uint32) (o *Object, found bool) {
	os.objectmutex.RLock()
	index, idfound := os.idindex[id]
	if idfound {
		o = os.asarray[index]
		found = true
	}
	os.objectmutex.RUnlock()
	return
}

func (os *Objects) MergeOrAdd(attribute Attribute, value AttributeValue, flexinit ...interface{}) (*Object, bool) {
	o, found := os.FindMultiOrAdd(attribute, value, func() *Object {
		// Add this is not found
		return NewObject(append(flexinit, attribute, value)...)
	})
	if found {
		eatme := NewObject(append(flexinit, attribute, value)...)
		// Use the first one found
		o[0].Absorb(eatme)
		return o[0], true
	}
	return o[0], false
}

func (os *Objects) FindOrAddObject(o *Object) bool {
	_, found := os.FindMultiOrAdd(DistinguishedName, o.OneAttr(DistinguishedName), func() *Object {
		return o
	})
	return found
}

func (os *Objects) FindOrAdd(attribute Attribute, value AttributeValue, flexinit ...interface{}) (*Object, bool) {
	o, found := os.FindMultiOrAdd(attribute, value, func() *Object {
		return NewObject(append(flexinit, attribute, value)...)
	})
	return o[0], found
}

func (os *Objects) Find(attribute Attribute, value AttributeValue) (o *Object, found bool) {
	v, found := os.FindMultiOrAdd(attribute, value, nil)
	if len(v) != 1 {
		return nil, false
	}
	return v[0], found
}

func (os *Objects) FindTwo(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue) (o *Object, found bool) {
	results, found := os.FindTwoMulti(attribute, value, attribute2, value2)
	if !found {
		return nil, false
	}
	return results[0], len(results) == 1
}

func (os *Objects) FindTwoOrAdd(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue, flexinit ...interface{}) (o *Object, found bool) {
	results, found := os.FindTwoMultiOrAdd(attribute, value, attribute2, value2, func() *Object {
		return NewObject(append(flexinit, attribute, value, attribute2, value2)...)
	})
	if !found {
		return results[0], false
	}
	return results[0], len(results) == 1
}

func (os *Objects) FindTwoMulti(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue) (o []*Object, found bool) {
	return os.FindTwoMultiOrAdd(attribute, value, attribute2, value2, nil)
}

func (os *Objects) FindMulti(attribute Attribute, value AttributeValue) ([]*Object, bool) {
	return os.FindTwoMultiOrAdd(attribute, value, NonExistingAttribute, nil, nil)
}

func (os *Objects) FindMultiOrAdd(attribute Attribute, value AttributeValue, addifnotfound func() *Object) ([]*Object, bool) {
	return os.FindTwoMultiOrAdd(attribute, value, NonExistingAttribute, nil, addifnotfound)
}

func (os *Objects) FindTwoMultiOrAdd(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue, addifnotfound func() *Object) ([]*Object, bool) {
	if attribute2 != NonExistingAttribute && attribute < attribute2 {
		attribute, attribute2 = attribute2, attribute
		value, value2 = value2, value
	}

	// Just lookup, no adding
	if addifnotfound == nil {
		if attribute2 == NonExistingAttribute {
			// Lookup by one attribute
			matches, found := os.GetIndex(attribute).Lookup(AttributeValueToIndex(value))
			return matches, found
		} else {
			// Lookup by two attributes
			matches, found := os.GetMultiIndex(attribute, attribute2).Lookup(multiindexkey{AttributeValueToIndex(value), AttributeValueToIndex(value2)})
			return matches, found
		}
	}

	// Add if not found
	os.objectmutex.Lock() // Prevent anyone from adding to objects while we're searching

	if attribute2 == NonExistingAttribute {
		// Lookup by one attribute
		matches, found := os.GetIndex(attribute).Lookup(AttributeValueToIndex(value))
		if found {
			os.objectmutex.Unlock()
			return matches, found
		}
	} else {
		// Lookup by two attributes
		matches, found := os.GetMultiIndex(attribute, attribute2).Lookup(multiindexkey{AttributeValueToIndex(value), AttributeValueToIndex(value2)})
		if found {
			os.objectmutex.Unlock()
			return matches, found
		}
	}

	// Create new object
	no := addifnotfound()
	if no != nil {
		if len(os.DefaultValues) > 0 {
			no.SetFlex(os.DefaultValues...)
		}
		os.add(no)
		os.objectmutex.Unlock()
		return []*Object{no}, false
	}
	os.objectmutex.Unlock()
	return nil, false
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
	o, _ := os.FindMultiOrAdd(ObjectSid, AttributeValueSID(s), func() *Object {
		no := NewObject(
			ObjectSid, AttributeValueSID(s),
		)
		if os.DefaultValues != nil {
			no.SetFlex(os.DefaultValues...)
		}
		return no
	})
	return o[0]
}

func (os *Objects) FindOrAddAdjacentSID(s windowssecurity.SID, r *Object) *Object {
	switch s.Component(2) {
	case 21: // Full "domain" SID
		result, _ := os.FindMultiOrAdd(ObjectSid, AttributeValueSID(s), func() *Object {
			no := NewObject(
				ObjectSid, AttributeValueSID(s),
				DataLoader, "FindOrAddAdjacentSID",
				IgnoreBlanks,
				DomainContext, r.Attr(DomainContext),
			)
			if !r.SID().IsNull() {
				if r.SID().StripRID() == s.StripRID() {
					// Same domain ... hmm!
				} else {
					// Other domain, then it's a foreign principal
					no.SetFlex(ObjectCategorySimple, "Foreign-Security-Principal")
					if domainContext := r.OneAttrString(DomainContext); domainContext != "" {
						no.SetFlex(DistinguishedName, "CN="+s.String()+",CN=ForeignSecurityPrincipals,"+domainContext)
					}
				}
			}
			return no
		})
		return result[0]
	default:
		if r.HasAttr(DomainContext) {
			// From outside, we need to find the domain part
			if o, found := os.FindTwoMulti(ObjectSid, AttributeValueSID(s), DomainContext, r.OneAttr(DomainContext)); found {
				return o[0]
			}
		}
		// From inside same source, that is easy
		if r.HasAttr(DataSource) {
			if o, found := os.FindTwoMulti(ObjectSid, AttributeValueSID(s), DataSource, r.OneAttr(DataSource)); found {
				return o[0]
			}
		}

	}

	// Not found, we have write lock so create it
	no := NewObject(ObjectSid, AttributeValueSID(s))

	if s.Component(2) != 21 {
		no.SetFlex(
			IgnoreBlanks,
			DomainContext, r.Attr(DomainContext),
			DataSource, r.Attr(DataSource),
		)
	}

	os.Add(no)

	return no
}

func findMostLocal(os []*Object) *Object {
	if len(os) == 0 {
		return nil
	}

	// There can only be one, so return it
	if len(os) == 1 {
		return os[0]
	}

	// Find the most local
	for _, o := range os {
		if strings.Contains(o.DN(), ",CN=ForeignSecurityPrincipals,") {
			return o
		}
	}

	// If we get here, we have more than one, and none of them are foreign
	return os[0]
}

func (os *Objects) FindGUID(g uuid.UUID) (o *Object, found bool) {
	return os.Find(ObjectGUID, AttributeValueGUID(g))
}
