package engine

import (
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	gsync "github.com/SaveTheRbtz/generic-sync-map-go"
	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/util"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

type typestatistics [256]int

type NodeIndex uint32
type EdgeCombo uint16

type IndexedGraph struct {
	Datapath      string
	root          *Node
	DefaultValues []any

	// Node tracking
	nodeMutex  sync.RWMutex
	nodeLookup gsync.MapOf[*Node, NodeIndex] // map to index in objects
	nodes      []*Node                       // All objects, int -> *Node

	// Edge tracking
	edgeComboLookup map[EdgeBitmap]EdgeCombo
	edgeCombos      []EdgeBitmap
	edges           [2]map[NodeIndex]map[NodeIndex]EdgeCombo // from index -> to index -> edgeCombo
	edgeComboMutex  sync.RWMutex                             // When we're not bulk loading

	bulkloading   bool // If true, we are bulk loading, so defer some operations
	bulkWorkers   sync.WaitGroup
	incomingEdges chan BulkEdgeRequest // Channel to receive incoming edges during bulk load
	flushEdges    chan struct{}        // Channel to request flushing of buffered edges
	edgeMutex     sync.RWMutex         // When we're not bulk loading

	// Lookups
	indexlock    sync.RWMutex
	indexes      []*Index                      // Uses atribute directly as slice offset for performance
	multiindexes map[AttributePair]*MultiIndex // Uses a map for storage considerations

	typecount typestatistics
}

func NewIndexedGraph() *IndexedGraph {
	g := IndexedGraph{
		// indexes:      make(map[Attribute]*Index),
		multiindexes:    make(map[AttributePair]*MultiIndex),
		edgeComboLookup: make(map[EdgeBitmap]EdgeCombo, 1024),
		edgeCombos:      make([]EdgeBitmap, 0, 1024),
		edges: [2]map[NodeIndex]map[NodeIndex]EdgeCombo{
			make(map[NodeIndex]map[NodeIndex]EdgeCombo, 8192), make(map[NodeIndex]map[NodeIndex]EdgeCombo, 8192)},
	}

	// Super important for this to work!
	blank := EdgeBitmap{}
	g.edgeCombos = append(g.edgeCombos, blank)
	g.edgeComboLookup[blank] = 0

	// unique := uintptr(unsafe.Pointer(&g))
	// ui.Debug().Msgf("IndexedGraph %v created!", unique)

	// runtime.AddCleanup(&g, func(g uintptr) {
	// 	ui.Debug().Msgf("IndexedGraph %v freed!", g)
	// }, unique)

	return &g
}

func (g *IndexedGraph) BulkLoadEdges(enable bool) bool {
	var result bool
	g.nodeMutex.Lock()
	if !g.bulkloading && enable {
		g.bulkloading = true
		g.incomingEdges = make(chan BulkEdgeRequest, 32768)
		g.flushEdges = make(chan struct{}, 5)
		g.bulkWorkers.Add(1)
		go g.processIncomingEdges(32768)
		result = true
	} else if g.bulkloading && !enable {
		close(g.incomingEdges)
		close(g.flushEdges)
		g.bulkloading = false
		result = true
		g.bulkWorkers.Wait()
	}
	g.nodeMutex.Unlock()
	return result
}

func (g *IndexedGraph) FlushEdges() bool {
	var result bool
	g.nodeMutex.Lock()
	if g.bulkloading {
		g.flushEdges <- struct{}{}
		result = true
	}
	g.nodeMutex.Unlock()
	return result
}

func (os *IndexedGraph) AddDefaultFlex(data ...any) {
	os.DefaultValues = append(os.DefaultValues, data...)
}

func (os *IndexedGraph) GetIndex(attribute Attribute) *Index {
	os.indexlock.RLock()

	// No room for index for this attribute
	if len(os.indexes) <= int(attribute) {
		os.indexlock.RUnlock()
		os.indexlock.Lock()
		// Someone might have beaten us to it?
		if len(os.indexes) <= int(attribute) {
			newindexes := make([]*Index, attribute+1)
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

func (os *IndexedGraph) GetMultiIndex(attribute, attribute2 Attribute) *MultiIndex {
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

func (os *IndexedGraph) refreshIndex(attribute Attribute, index *Index) {
	index.init()

	// add all existing stuff to index
	os.Iterate(func(o *Node) bool {
		o.Attr(attribute).Iterate(func(value AttributeValue) bool {
			// Add to index
			index.Add(value, o, false)
			return true // continue
		})
		return true
	})
}

func (os *IndexedGraph) refreshMultiIndex(attribute, attribute2 Attribute, index *MultiIndex) {
	index.init()

	// add all existing stuff to index
	os.Iterate(func(o *Node) bool {
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

func (os *IndexedGraph) SetRoot(ro *Node) {
	os.root = ro
}

func (os *IndexedGraph) DropIndexes() {
	// Clear all indexes
	os.indexlock.Lock()
	os.indexes = make([]*Index, 0)
	os.multiindexes = make(map[AttributePair]*MultiIndex)
	os.indexlock.Unlock()
}

func (os *IndexedGraph) DropIndex(attribute Attribute) {
	// Clear all indexes
	os.indexlock.Lock()
	if len(os.indexes) > int(attribute) {
		os.indexes[attribute] = nil
	}
	os.indexlock.Unlock()
}

func (os *IndexedGraph) ReindexObject(o *Node, isnew bool) {
	// Single attribute indexes
	os.indexlock.RLock()
	for i, index := range os.indexes {
		if index != nil {
			attribute := Attribute(i)
			o.AttrRendered(attribute).Iterate(func(value AttributeValue) bool {
				// If it's a string, lowercase it before adding to index, we do the same on lookups
				indexval := AttributeValueToIndex(value)

				unique := attribute.HasFlag(Unique)

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

func AttributeValueToIndex(value AttributeValue) AttributeValue {
	if value == nil {
		return nil
	}
	if s, ok := value.(attributeValueString); ok {
		return NV(strings.ToLower(s.String()))
	}
	return value
}

func (os *IndexedGraph) Filter(evaluate func(o *Node) bool) *IndexedGraph {
	result := NewIndexedGraph()

	os.Iterate(func(n *Node) bool {
		if evaluate(n) {
			result.Add(n)
		}
		return true
	})
	return result
}

func (os *IndexedGraph) AddNew(flexinit ...any) *Node {
	o := NewNode(flexinit...)
	if os.DefaultValues != nil {
		o.setFlex(os.DefaultValues...)
	}
	os.AddMerge(nil, nil, o)
	return o
}

func (os *IndexedGraph) Add(obs *Node) {
	os.nodeMutex.Lock() // This is due to FindOrAdd consistency
	os.add(obs)
	os.nodeMutex.Unlock()
}

func (os *IndexedGraph) AddMerge(mergeAttr, conflictAttr []Attribute, nodes ...*Node) {
	for _, inconingNode := range nodes {
		var processed bool
		if len(mergeAttr) > 0 {
			_, processed = os.Merge(mergeAttr, conflictAttr, inconingNode)
		}
		if !processed {
			os.nodeMutex.Lock() // This is due to FindOrAdd consistency
			os.add(inconingNode)
			os.nodeMutex.Unlock()
		}
	}
}

func (os *IndexedGraph) Contains(o *Node) bool {
	_, found := os.nodeLookup.Load(o)
	return found
}

func (os *IndexedGraph) IndexToNode(id NodeIndex) (*Node, bool) {
	if len(os.nodes) <= int(id) {
		return nil, false
	}
	return os.nodes[id], true
}

func (os *IndexedGraph) NodeToIndex(node *Node) (NodeIndex, bool) {
	return os.nodeLookup.Load(node)
}

func (os *IndexedGraph) LookupNodeByID(id NodeID) (*Node, bool) {
	return os.Find(AttributeNodeId, NV(int(id)))
}

// Attemps to merge the node into the objects
func (os *IndexedGraph) Merge(attrtomerge, singleattrs []Attribute, source *Node) (*Node, bool) {
	var mergedTo *Node
	var merged bool

	sourceType := source.Type()

	if len(attrtomerge) > 0 {
		for _, mergeattr := range attrtomerge {
			source.Attr(mergeattr).Iterate(func(lookfor AttributeValue) bool {

				if mergetargets, found := os.FindMulti(mergeattr, lookfor); found {
					mergetargets.Iterate(func(target *Node) bool {
						// Test if types mismatch violate this merge
						targetType := target.Type()
						if targetType != NodeTypeOther && sourceType != NodeTypeOther && targetType != sourceType {
							// Merge conflict, can't merge different types
							ui.Trace().Msgf("Merge failure due to type difference, not merging %v of type %v with %v of type %v", source.Label(), sourceType.String(), target.Label(), targetType.String())
							return true // continue
						}

						// Test if any single attribute holding values violate this merge
						var failed bool
						var sv, tv AttributeValues
						for _, attr := range singleattrs {
							sv = source.Attr(attr)
							if sv == nil {
								continue
							}
							tv = target.Attr(attr)
							if tv == nil {
								continue
							}
							if !CompareAttributeValues(sv.First(), tv.First()) {
								// Conflicting attribute values, we can't merge these
								ui.Trace().Msgf("Not merging %v into %v on %v with value '%v', as attribute %v is different (%v != %v)", source.Label(), target.Label(), mergeattr.String(), lookfor.String(), attr.String(), sv.First().String(), tv.First().String())
								failed = true
								break
							}
						}
						if failed {
							return true // break
						}

						for _, mfi := range mergeapprovers {
							res, err := mfi.mergefunc(source, target)
							switch err {
							case ErrDontMerge:
								ui.Trace().Msgf("Merge approver %v rejected merging %v with %v on attribute %v", mfi.name, source.Label(), target.Label(), mergeattr.String())
								return true
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
						mergedTo = target
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

	if merged {
		// If the source has a parent, but the target doesn't we assimilate that role (muhahaha)
		if source.parent != nil {
			moveto := source.parent

			if mergedTo.parent == nil {
				mergedTo.parent = moveto
				moveto.children.Add(mergedTo)
			}
			if moveto == source.parent {
				moveto.removeChild(source)
			}
			source.parent = nil
		}

		source.children.Iterate(func(child *Node) bool {
			if child.parent != source {
				panic("Child/parent mismatch")
			}
			mergedTo.children.Add(child)

			child.parent = mergedTo
			return true
		})
		source.children = NodeSlice{}

		// Move the securitydescriptor, as we dont have the attribute saved to regenerate it (we throw it away at import after populating the cache)
		if source.sdcache != nil && mergedTo.sdcache != nil {
			// Both has a cache
			if !source.sdcache.Equals(mergedTo.sdcache) {
				// Different caches, so we need to merge them which is impossible
				ui.Error().Msgf("Can not merge security descriptors between %v and %v", source.Label(), mergedTo.Label())
			}
		} else if mergedTo.sdcache == nil && source.sdcache != nil {
			mergedTo.sdcache = source.sdcache
		}

		mergedTo.objecttype = 0 // Recalculate this
	}
	return mergedTo, merged
}

func (os *IndexedGraph) add(newNode *Node) {
	if _, found := os.nodeLookup.LoadOrStore(newNode, NodeIndex(len(os.nodes))); !found {
		if os.DefaultValues != nil {
			newNode.setFlex(os.DefaultValues...)
		}
		os.nodes = append(os.nodes, newNode)
		os.ReindexObject(newNode, true)
		os.typecount[newNode.Type()]++
	} else {
		panic("Node already exists in graph, so we can't add it")
	}
}

func (os *IndexedGraph) AddRelaxed(newNode *Node) {
	os.nodeMutex.Lock()
	if _, found := os.nodeLookup.LoadOrStore(newNode, NodeIndex(len(os.nodes))); !found {
		if os.DefaultValues != nil {
			newNode.setFlex(os.DefaultValues...)
		}
		os.nodes = append(os.nodes, newNode)
		os.ReindexObject(newNode, true)
		os.typecount[newNode.Type()]++
	}
	os.nodeMutex.Unlock()
}

// First node added is the root object
func (os *IndexedGraph) Root() *Node {
	return os.root
}

func (os *IndexedGraph) Statistics() typestatistics {
	os.nodeMutex.RLock()
	defer os.nodeMutex.RUnlock()
	return os.typecount
}

func (os *IndexedGraph) AsSlice() NodeSlice {
	result := NewNodeSlice(os.Order())
	os.Iterate(func(o *Node) bool {
		result.Add(o)
		return true
	})
	return result
}

func (os *IndexedGraph) Order() int {
	return len(os.nodes)
}

func (os *IndexedGraph) Size() int {
	var count int
	for _, em := range os.edges[0] {
		count += len(em)
	}
	return count
}

func (os *IndexedGraph) Iterate(each func(o *Node) bool) {
	for _, n := range os.nodes {
		if !each(n) {
			return
		}
	}
}

func (os *IndexedGraph) IterateParallel(each func(o *Node) bool, parallelFuncs int) {
	if parallelFuncs == 0 {
		parallelFuncs = runtime.NumCPU()
	}
	queue := make(chan *Node, parallelFuncs*2)
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
	os.Iterate(func(o *Node) bool {
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

func (os *IndexedGraph) MergeOrAdd(attribute Attribute, value AttributeValue, flexinit ...any) (*Node, bool) {
	results, found := os.FindMultiOrAdd(attribute, value, func() *Node {
		// Add this is not found
		return NewNode(append(flexinit, attribute, value)...)
	})
	if found {
		eatme := NewNode(append(flexinit, attribute, value)...)
		// Use the first one found
		target := results.First()
		target.Absorb(eatme)
		return target, true
	}
	return results.First(), false
}

func (os *IndexedGraph) FindOrAddObject(o *Node) bool {
	_, found := os.FindMultiOrAdd(DistinguishedName, o.OneAttr(DistinguishedName), func() *Node {
		return o
	})
	return found
}

func (os *IndexedGraph) FindOrAdd(attribute Attribute, value AttributeValue, flexinit ...any) (*Node, bool) {
	o, found := os.FindMultiOrAdd(attribute, value, func() *Node {
		return NewNode(append(flexinit, attribute, value)...)
	})
	return o.First(), found
}

func (os *IndexedGraph) Find(attribute Attribute, value AttributeValue) (o *Node, found bool) {
	v, found := os.FindMultiOrAdd(attribute, value, nil)
	if v.Len() != 1 {
		return nil, false
	}
	return v.First(), found
}

func (os *IndexedGraph) FindTwo(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue) (o *Node, found bool) {
	results, found := os.FindTwoMulti(attribute, value, attribute2, value2)
	if !found {
		return nil, false
	}
	return results.First(), results.Len() == 1
}

func (os *IndexedGraph) FindTwoOrAdd(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue, flexinit ...any) (o *Node, found bool) {
	results, found := os.FindTwoMultiOrAdd(attribute, value, attribute2, value2, func() *Node {
		return NewNode(append(flexinit, attribute, value, attribute2, value2)...)
	})
	if !found {
		return results.First(), false
	}
	return results.First(), results.Len() == 1
}

func (os *IndexedGraph) FindTwoMulti(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue) (o NodeSlice, found bool) {
	return os.FindTwoMultiOrAdd(attribute, value, attribute2, value2, nil)
}

func (os *IndexedGraph) FindMulti(attribute Attribute, value AttributeValue) (NodeSlice, bool) {
	return os.FindTwoMultiOrAdd(attribute, value, NonExistingAttribute, nil, nil)
}

func (os *IndexedGraph) FindMultiOrAdd(attribute Attribute, value AttributeValue, addifnotfound func() *Node) (NodeSlice, bool) {
	return os.FindTwoMultiOrAdd(attribute, value, NonExistingAttribute, nil, addifnotfound)
}

func (os *IndexedGraph) FindTwoMultiOrAdd(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue, addifnotfound func() *Node) (NodeSlice, bool) {
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
	os.nodeMutex.Lock() // Prevent anyone from adding to objects while we're searching

	if attribute2 == NonExistingAttribute {
		// Lookup by one attribute
		matches, found := os.GetIndex(attribute).Lookup(AttributeValueToIndex(value))
		if found {
			os.nodeMutex.Unlock()
			return matches, found
		}
	} else {
		// Lookup by two attributes
		matches, found := os.GetMultiIndex(attribute, attribute2).Lookup(value, value2)
		if found {
			os.nodeMutex.Unlock()
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
		os.nodeMutex.Unlock()
		nos := NewNodeSlice(1)
		nos.Add(no)
		return nos, false
	}
	os.nodeMutex.Unlock()
	return NodeSlice{}, false
}

func (os *IndexedGraph) DistinguishedParent(o *Node) (*Node, bool) {
	DN := o.DN()
	if DN == "" {
		return nil, false
	}

	parentDN := util.ParentDistinguishedName(DN)
	if parentDN == "" {
		return nil, false
	}

	// Use node chaining if possible
	directparent := o.Parent()
	if directparent != nil && strings.EqualFold(directparent.OneAttrString(DistinguishedName), parentDN) {
		return directparent, true
	}

	return os.Find(DistinguishedName, NV(parentDN))
}

func (os *IndexedGraph) Subordinates(o *Node) *IndexedGraph {
	return os.Filter(func(o2 *Node) bool {
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

func (os *IndexedGraph) FindOrAddSID(s windowssecurity.SID) *Node {
	o, _ := os.FindMultiOrAdd(ObjectSid, NV(s), func() *Node {
		no := NewNode(
			ObjectSid, NV(s),
		)
		if os.DefaultValues != nil {
			no.SetFlex(os.DefaultValues...)
		}
		return no
	})
	return o.First()
}

func (os *IndexedGraph) FindOrAddAdjacentSID(s windowssecurity.SID, r *Node, flexinit ...any) *Node {
	sidobject, _ := os.FindOrAddAdjacentSIDFound(s, r, flexinit...)
	return sidobject
}

func (os *IndexedGraph) FindOrAddAdjacentSIDFound(s windowssecurity.SID, relativeTo *Node, flexinit ...any) (*Node, bool) {
	if relativeTo == nil {
		return os.FindOrAdd(ObjectSid, NV(s))
	}

	// If it's relative to a computer, then let's see if we can find it (there could be SID collisions across local machines)
	if relativeTo.Type() == NodeTypeMachine && relativeTo.HasAttr(DataSource) {
		// Test whether this SID is relative to the computer (this solves problem with machines having the same machine SIDs)
		if s.StripRID() == relativeTo.SID() {
			// See if we can find or create it relative to the computer
			return os.FindTwoOrAdd(ObjectSid, NV(s), DataSource, relativeTo.OneAttr(DataSource))
		}
	}

	if s.Component(2) == 21 && s.Component(3) != 0 {
		// Let's assume it's not relative to a computer, and therefore truly unique
		result, found := os.FindMultiOrAdd(ObjectSid, NV(s), func() *Node {
			no := NewNode(
				ObjectSid, NV(s),
			)
			no.SetFlex(flexinit...)
			return no
		})
		return result.First(), found
	}

	// This is relative to an node that is part of a domain, so lets use that as a lookup reference
	if relativeTo.HasAttr(DomainContext) {
		if o, found := os.FindTwoMulti(ObjectSid, NV(s), DomainContext, relativeTo.OneAttr(DomainContext)); found {
			return o.First(), true
		}
	}

	// Use the object's datasource as the relative reference
	if relativeTo.HasAttr(DataSource) {
		if o, found := os.FindTwoMulti(ObjectSid, NV(s), DataSource, relativeTo.OneAttr(DataSource)); found {
			return o.First(), true
		}
	}

	// Not found, so fall back to just looking up the SID
	no, found := os.FindOrAdd(ObjectSid, NV(s),
		IgnoreBlanks,
		DomainContext, relativeTo.Attr(DomainContext),
		DataSource, relativeTo.Attr(DataSource),
	)
	return no, found
}

func (os *IndexedGraph) FindGUID(g uuid.UUID) (o *Node, found bool) {
	return os.Find(ObjectGUID, NV(g))
}
