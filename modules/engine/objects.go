package engine

import (
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gsync "github.com/SaveTheRbtz/generic-sync-map-go"
	"github.com/akyoto/cache"
	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/util"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

var idcounter uint32 // Unique ID +1 to assign to Object added to this collection if it's zero

type typestatistics [256]int

type Objects struct {
	Datapath      string
	root          *Object
	DefaultValues []any
	objects       gsync.MapOf[ObjectID, *Object]
	multiindexes  map[AttributePair]*MultiIndex // Uses a map for storage considerations

	indexes []*Index // Uses atribute directly as slice offset for performance

	objectmutex sync.RWMutex

	indexlock sync.RWMutex

	typecount typestatistics
}

func NewObjects() *Objects {
	os := Objects{
		// indexes:      make(map[Attribute]*Index),
		multiindexes: make(map[AttributePair]*MultiIndex),
	}
	return &os
}

func (os *Objects) AddDefaultFlex(data ...any) {
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
}

func (os *Objects) GetMultiIndex(attribute, attribute2 Attribute) *MultiIndex {
	// Consistently map to the right index no matter what order they are called
	if attribute > attribute2 {
		attribute, attribute2 = attribute2, attribute
	}

	if attribute2 == NonExistingAttribute {
		panic("Cannot create multi-index with non-existing attribute")
	}

	os.indexlock.RLock()

	// No room for index for this attribute
	indexkey := AttributePair{attribute, attribute2}

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

	index = &MultiIndex{}

	// Initialize index and add existing stuff
	os.refreshMultiIndex(attribute, attribute2, index)

	os.multiindexes[indexkey] = index

	os.indexlock.Unlock()

	return index
}

func (os *Objects) refreshIndex(attribute Attribute, index *Index) {
	index.init()

	// add all existing stuff to index
	os.Iterate(func(o *Object) bool {
		o.Attr(attribute).Iterate(func(value AttributeValue) bool {
			// Add to index
			index.Add(value, o, false)
			return true // continue
		})
		return true
	})
}

func (os *Objects) refreshMultiIndex(attribute, attribute2 Attribute, index *MultiIndex) {
	index.init()

	// add all existing stuff to index
	os.Iterate(func(o *Object) bool {
		if !o.HasAttr(attribute) || !o.HasAttr(attribute2) {
			return true
		}

		o.Attr(attribute).Iterate(func(value AttributeValue) bool {
			iv := AttributeValueToIndex(value)
			o.Attr(attribute2).Iterate(func(value2 AttributeValue) bool {
				iv2 := AttributeValueToIndex(value2)
				// Add to index
				index.Add(iv, iv2, o, false)

				return true
			})
			return true
		})
		return true
	})
}

func (os *Objects) SetRoot(ro *Object) {
	os.root = ro
}

func (os *Objects) DropIndexes() {
	// Clear all indexes
	os.indexlock.Lock()
	os.indexes = make([]*Index, 0)
	os.multiindexes = make(map[AttributePair]*MultiIndex)
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
	// Single attribute indexes
	os.indexlock.RLock()
	for i, index := range os.indexes {
		if index != nil {
			attribute := Attribute(i)
			o.AttrRendered(attribute).Iterate(func(value AttributeValue) bool {
				// If it's a string, lowercase it before adding to index, we do the same on lookups
				indexval := AttributeValueToIndex(value)

				unique := attribute.IsUnique()

				if isnew && unique {
					existing, dupe := index.Lookup(indexval)
					if dupe {
						if existing.First() != o {
							ui.Warn().Msgf("Duplicate index %v value %v when trying to add %v, already exists as %v, index still points to original object", attribute.String(), value.String(), o.Label(), existing.First().Label())
							return true
						}
					}
				}

				index.Add(indexval, o, !isnew)
				return true
			})
		}
	}

	// Multi indexes
	for attributes, index := range os.multiindexes {
		attribute := attributes.attribute1
		attribute2 := attributes.attribute2

		if !o.HasAttr(attribute) || !o.HasAttr(attribute2) {
			continue
		}

		o.Attr(attribute).Iterate(func(value AttributeValue) bool {
			key := AttributeValueToIndex(value)
			o.Attr(attribute2).Iterate(func(value2 AttributeValue) bool {
				key2 := AttributeValueToIndex(value2)

				index.Add(key, key2, o, !isnew)

				return true
			})
			return true
		})
	}
	os.indexlock.RUnlock()
}

var avtiCache = cache.New(time.Second * 30)

func AttributeValueToIndex(value AttributeValue) AttributeValue {
	if value == nil {
		return nil
	}
	if _, ok := value.(AttributeValueString); ok {
		s := value.String()
		if lowered, found := avtiCache.Get(s); found {
			return lowered.(AttributeValue)
		}
		lowered := NewAttributeValueString(strings.ToLower(s))
		avtiCache.Set(s, lowered, time.Second*30)
		return lowered
	}
	return value
}

func (os *Objects) Filter(evaluate func(o *Object) bool) *Objects {
	result := NewObjects()

	os.Iterate(func(object *Object) bool {
		if evaluate(object) {
			result.Add(object)
		}
		return true
	})
	return result
}

func (os *Objects) AddNew(flexinit ...any) *Object {
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
		if len(attrtomerge) == 0 || !os.Merge(attrtomerge, o) {
			os.objectmutex.Lock() // This is due to FindOrAdd consistency
			os.add(o)
			os.objectmutex.Unlock()
		}
	}
}

func (os *Objects) Contains(o *Object) bool {
	_, found := os.FindID(o.ID())
	return found
}

// Attemps to merge the object into the objects
func (os *Objects) Merge(attrtomerge []Attribute, source *Object) bool {
	if _, found := os.FindID(source.ID()); found {
		ui.Fatal().Msg("Object already exists in objects, so we can't merge it")
	}

	var merged bool

	sourceType := source.Type()

	if len(attrtomerge) > 0 {
		for _, mergeattr := range attrtomerge {
			source.Attr(mergeattr).Iterate(func(lookfor AttributeValue) bool {

				if mergetargets, found := os.FindMulti(mergeattr, lookfor); found {
					mergetargets.Iterate(func(target *Object) bool {
						// Test if types mismatch violate this merge
						targetType := target.Type()
						if targetType != ObjectTypeOther && sourceType != ObjectTypeOther && targetType != sourceType {
							// Merge conflict, can't merge different types
							ui.Trace().Msgf("Merge failure due to type difference, not merging %v of type %v with %v of type %v", source.Label(), sourceType.String(), target.Label(), targetType.String())
							return false // continue
						}

						var failed bool

						// Test if there are incoming or outgoing edges pointing at each other
						source.edges[In].Range(func(pointingFrom *Object, value EdgeBitmap) bool {
							if target == pointingFrom {
								failed = true
								return false
							}
							return true
						})
						if failed {
							return false // continue
						}
						source.edges[Out].Range(func(pointingTo *Object, value EdgeBitmap) bool {
							if target == pointingTo {
								failed = true
								return false
							}
							return true
						})
						if failed {
							return false // continue
						}

						// Test if any single attribute holding values violate this merge
						source.AttrIterator(func(attr Attribute, sourceValues AttributeValues) bool {
							if attr.IsSingle() && target.HasAttr(attr) {
								if !CompareAttributeValues(sourceValues.First(), target.Attr(attr).First()) {
									// Conflicting attribute values, we can't merge these
									ui.Trace().Msgf("Not merging %v into %v on %v with value '%v', as attribute %v is different (%v != %v)", source.Label(), target.Label(), mergeattr.String(), lookfor.String(), attr.String(), sourceValues.First().String(), target.Attr(attr).First().String())
									failed = true
									return false
								}
							}
							return true
						})
						if failed {
							return false // break
						}

						for _, mfi := range mergeapprovers {
							res, err := mfi.mergefunc(source, target)
							switch err {
							case ErrDontMerge:
								ui.Trace().Msgf("Merge approver %v rejected merging %v with %v on attribute %v", mfi.name, source.Label(), target.Label(), mergeattr.String())
								return false // break
							case ErrMergeOnThis, nil:
								// Let the code below do the merge
							default:
								ui.Fatal().Msgf("Error merging %v: %v", source.Label(), err)
							}
							if res != nil {
								// Custom merge - how do we handle this?
								ui.Fatal().Msgf("Custom merge function not supported yet")
							}
						}

						// ui.Trace().Msgf("Merging %v with %v on attribute %v", o.Label(), mergetarget.Label(), mergeattr.String())
						attributeinfos[int(mergeattr)].mergeSuccesses.Add(1)

						target.Absorb(source)
						os.ReindexObject(target, false)
						merged = true
						return false
					})
				}
				return !merged
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
		panic("Objects must have a unique ID")
	}

	if _, found := os.objects.LoadOrStore(o.ID(), o); found {
		panic("Object already exists in objects, so we can't add it")
	}

	if os.DefaultValues != nil {
		o.setFlex(os.DefaultValues...)
	}

	os.ReindexObject(o, true)

	// Statistics
	os.typecount[o.Type()]++
}

func (os *Objects) AddRelaxed(o *Object) {
	if o.id == 0 {
		panic("Objects must have a unique ID")
	}

	if _, found := os.objects.LoadOrStore(o.ID(), o); !found {
		if os.DefaultValues != nil {
			o.setFlex(os.DefaultValues...)
		}
		os.ReindexObject(o, true)
	}
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

func (os *Objects) AsSlice() ObjectSlice {
	result := NewObjectSlice(os.Len())
	os.Iterate(func(o *Object) bool {
		result.Add(o)
		return true
	})
	return result
}

func (os *Objects) Len() int {
	var count int
	os.objects.Range(func(key ObjectID, value *Object) bool {
		count++
		return true
	})
	return count
}

func (os *Objects) Iterate(each func(o *Object) bool) {
	os.objects.Range(func(key ObjectID, value *Object) bool {
		return each(value)
	})
}

func (os *Objects) IterateID(each func(id ObjectID) bool) {
	os.objects.Range(func(key ObjectID, value *Object) bool {
		return each(key)
	})
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
					stop.Store(true)
				}
			}
			wg.Done()
		}()
	}

	var i int
	os.Iterate(func(o *Object) bool {
		if i&0x3ff == 0 && stop.Load() {
			ui.Debug().Msg("Aborting parallel iterator for Objects")
			return false
		}
		queue <- o
		i++
		return true
	})

	close(queue)
	wg.Wait()
}

func (os *Objects) MergeOrAdd(attribute Attribute, value AttributeValue, flexinit ...any) (*Object, bool) {
	results, found := os.FindMultiOrAdd(attribute, value, func() *Object {
		// Add this is not found
		return NewObject(append(flexinit, attribute, value)...)
	})
	if found {
		eatme := NewObject(append(flexinit, attribute, value)...)
		// Use the first one found
		target := results.First()
		target.Absorb(eatme)
		return target, true
	}
	return results.First(), false
}

func (os *Objects) FindID(id ObjectID) (*Object, bool) {
	return os.objects.Load(id)
}

func (os *Objects) FindOrAddObject(o *Object) bool {
	_, found := os.FindMultiOrAdd(DistinguishedName, o.OneAttr(DistinguishedName), func() *Object {
		return o
	})
	return found
}

func (os *Objects) FindOrAdd(attribute Attribute, value AttributeValue, flexinit ...any) (*Object, bool) {
	o, found := os.FindMultiOrAdd(attribute, value, func() *Object {
		return NewObject(append(flexinit, attribute, value)...)
	})
	return o.First(), found
}

func (os *Objects) Find(attribute Attribute, value AttributeValue) (o *Object, found bool) {
	v, found := os.FindMultiOrAdd(attribute, value, nil)
	if v.Len() != 1 {
		return nil, false
	}
	return v.First(), found
}

func (os *Objects) FindTwo(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue) (o *Object, found bool) {
	results, found := os.FindTwoMulti(attribute, value, attribute2, value2)
	if !found {
		return nil, false
	}
	return results.First(), results.Len() == 1
}

func (os *Objects) FindTwoOrAdd(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue, flexinit ...any) (o *Object, found bool) {
	results, found := os.FindTwoMultiOrAdd(attribute, value, attribute2, value2, func() *Object {
		return NewObject(append(flexinit, attribute, value, attribute2, value2)...)
	})
	if !found {
		return results.First(), false
	}
	return results.First(), results.Len() == 1
}

func (os *Objects) FindTwoMulti(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue) (o ObjectSlice, found bool) {
	return os.FindTwoMultiOrAdd(attribute, value, attribute2, value2, nil)
}

func (os *Objects) FindMulti(attribute Attribute, value AttributeValue) (ObjectSlice, bool) {
	return os.FindTwoMultiOrAdd(attribute, value, NonExistingAttribute, nil, nil)
}

func (os *Objects) FindMultiOrAdd(attribute Attribute, value AttributeValue, addifnotfound func() *Object) (ObjectSlice, bool) {
	return os.FindTwoMultiOrAdd(attribute, value, NonExistingAttribute, nil, addifnotfound)
}

func (os *Objects) FindTwoMultiOrAdd(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue, addifnotfound func() *Object) (ObjectSlice, bool) {
	if attribute > attribute2 {
		attribute, attribute2 = attribute2, attribute
		value, value2 = value2, value
	}

	// Just lookup, no adding
	if addifnotfound == nil {
		if attribute2 == NonExistingAttribute {
			// Lookup by one attribute
			matches, found := os.GetIndex(attribute).Lookup(value)
			return matches, found
		} else {
			// Lookup by two attributes
			matches, found := os.GetMultiIndex(attribute, attribute2).Lookup(value, value2)
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
		matches, found := os.GetMultiIndex(attribute, attribute2).Lookup(value, value2)
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
		nos := NewObjectSlice(1)
		nos.Add(no)
		return nos, false
	}
	os.objectmutex.Unlock()
	return ObjectSlice{}, false
}

func (os *Objects) DistinguishedParent(o *Object) (*Object, bool) {
	dn := util.ParentDistinguishedName(o.DN())

	// Use object chaining if possible
	directparent := o.Parent()
	if directparent != nil && strings.EqualFold(directparent.OneAttrString(DistinguishedName), dn) {
		return directparent, true
	}

	return os.Find(DistinguishedName, NewAttributeValueString(dn))
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
	o, _ := os.FindMultiOrAdd(ObjectSid, NewAttributeValueSID(s), func() *Object {
		no := NewObject(
			ObjectSid, NewAttributeValueSID(s),
		)
		if os.DefaultValues != nil {
			no.SetFlex(os.DefaultValues...)
		}
		return no
	})
	return o.First()
}

func (os *Objects) FindOrAddAdjacentSID(s windowssecurity.SID, r *Object, flexinit ...any) *Object {
	sidobject, _ := os.FindOrAddAdjacentSIDFound(s, r, flexinit...)
	return sidobject
}

func (os *Objects) FindOrAddAdjacentSIDFound(s windowssecurity.SID, r *Object, flexinit ...any) (*Object, bool) {
	// If it's relative to a computer, then let's see if we can find it (there could be SID collisions across local machines)
	if r.Type() == ObjectTypeMachine && r.HasAttr(DataSource) {
		// See if we can find it relative to the computer
		if o, found := os.FindTwoMulti(ObjectSid, NewAttributeValueSID(s), DataSource, r.OneAttr(DataSource)); found {
			return o.First(), true
		}
	}

	// Let's assume it's not relative to a computer, and therefore truly unique
	if s.Component(2) == 21 && s.Component(3) != 0 {
		result, found := os.FindMultiOrAdd(ObjectSid, NewAttributeValueSID(s), func() *Object {
			no := NewObject(
				ObjectSid, NewAttributeValueSID(s),
			)
			no.SetFlex(flexinit...)
			return no
		})
		return result.First(), found
	}

	// This is relative to an object that is part of a domain, so lets use that as a lookup reference
	if r.HasAttr(DomainContext) {
		if o, found := os.FindTwoMulti(ObjectSid, NewAttributeValueSID(s), DomainContext, r.OneAttr(DomainContext)); found {
			return o.First(), true
		}
	}

	// Use the objects datasource as the relative reference
	if r.HasAttr(DataSource) {
		if o, found := os.FindTwoMulti(ObjectSid, NewAttributeValueSID(s), DataSource, r.OneAttr(DataSource)); found {
			return o.First(), true
		}
	}

	// Not found, so fall back to just looking up the SID
	no, found := os.FindOrAdd(ObjectSid, NewAttributeValueSID(s),
		IgnoreBlanks,
		DomainContext, r.Attr(DomainContext),
		DataSource, r.Attr(DataSource),
	)

	return no, found
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
	return os.Find(ObjectGUID, NewAttributeValueGUID(g))
}
