package engine

import (
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	gsync "github.com/SaveTheRbtz/generic-sync-map-go"
	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/util"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

type typestatistics [256]int

type NodeIndex uint32

type EdgeCombo uint16

type IndexedGraph struct {
	extensions    sync.Map
	Datapath      string
	root          *Node
	DefaultValues []any

	// Node tracking
	nodeMutex  sync.RWMutex
	nodeLookup nodePositions // node -> index in nodes
	// nodesVersion changes whenever nodes are added or removed; the ID
	// lookup is rebuilt from the nodes on first use after a change.
	nodesVersion atomic.Uint64
	idMutex      sync.RWMutex
	idLookup     map[NodeID]*Node
	idVersion    uint64
	nodes        []*Node // All objects, int -> *Node

	commitMutex sync.Mutex // one commit at a time

	// propertySets caches the property set (attributeSecurityGUID) each
	// attribute GUID belongs to, as found in this graph's schema.
	propertySets gsync.MapOf[uuid.UUID, uuid.UUID]

	// Edge tracking
	edgeCombos  *edgeComboTable
	edges       [2]adjacency    // by direction: from index -> to index -> edgeCombo
	provenance  provenanceIndex // why outgoing edges exist, see provenance.go; under edgeMutex
	sources     sourceTable
	edgeMutex   sync.RWMutex
	edgeVersion uint64 // changes whenever an edge is written, under edgeMutex

	// Lookups
	indexlock    sync.RWMutex
	indexes      []*Index                      // Uses atribute directly as slice offset for performance
	multiindexes map[AttributePair]*MultiIndex // Uses a map for storage considerations
	indexBuilds  map[any]chan struct{}         // indexes being built, by Attribute or AttributePair

	commitStats commitStats

	typecount typestatistics
	orphans   *Node // container for nodes without a parent, see FinishLoading

	// The loader each LoaderID's loader-phase processors see, by name.
	loaderScopes map[LoaderID]string
	loadRoots    []*Node // loaders' root nodes, added with their first commit

	// Parent links loaders claimed for nodes another loader created,
	// applied by applyParentClaims.
	parentClaimsMutex sync.Mutex
	parentClaims      []parentClaim

	canonicalMutex sync.Mutex
	canonicalRanks []uint32 // see CanonicalRanks
	rankedEdges    *RankedAdjacency
}

func NewIndexedGraph() *IndexedGraph {
	g := IndexedGraph{
		// indexes:      make(map[Attribute]*Index),
		multiindexes: make(map[AttributePair]*MultiIndex),
		edgeCombos:   newEdgeComboTable(),
	}

	// unique := uintptr(unsafe.Pointer(&g))
	// ui.Debug().Msgf("IndexedGraph %v created!", unique)

	// runtime.AddCleanup(&g, func(g uintptr) {
	// 	ui.Debug().Msgf("IndexedGraph %v freed!", g)
	// }, unique)

	g.nodeLookup.own()
	return &g
}

func (os *IndexedGraph) AddDefaultFlex(data ...any) {
	os.DefaultValues = append(os.DefaultValues, data...)
}

func (os *IndexedGraph) GetIndex(attribute Attribute) *Index {
	os.indexlock.RLock()
	if int(attribute) < len(os.indexes) {
		if index := os.indexes[attribute]; index != nil {
			os.indexlock.RUnlock()
			return index
		}
	}
	os.indexlock.RUnlock()

	for {
		os.indexlock.Lock()
		if len(os.indexes) <= int(attribute) {
			newindexes := make([]*Index, attribute+1)
			copy(newindexes, os.indexes)
			os.indexes = newindexes
		}
		if index := os.indexes[attribute]; index != nil {
			os.indexlock.Unlock()
			return index
		}
		if !os.claimIndexBuild(attribute) {
			continue
		}
		index := &Index{}
		os.refreshIndex(attribute, index)
		os.indexlock.Lock()
		os.indexes[attribute] = index
		os.finishIndexBuild(attribute)
		return index
	}
}

// claimIndexBuild is called holding indexlock and releases it. It returns
// true when the caller is to build the index; otherwise another caller is
// building it, and it returns once that build is done. Building an index
// scans the whole graph, so concurrent lookups of a missing index build it
// once instead of once each.
func (os *IndexedGraph) claimIndexBuild(key any) bool {
	if wait, building := os.indexBuilds[key]; building {
		os.indexlock.Unlock()
		<-wait
		return false
	}
	if os.indexBuilds == nil {
		os.indexBuilds = map[any]chan struct{}{}
	}
	os.indexBuilds[key] = make(chan struct{})
	os.indexlock.Unlock()
	return true
}

// finishIndexBuild is called holding indexlock, after storing the index,
// and releases it.
func (os *IndexedGraph) finishIndexBuild(key any) {
	done := os.indexBuilds[key]
	delete(os.indexBuilds, key)
	os.indexlock.Unlock()
	close(done)
}

func (os *IndexedGraph) GetMultiIndex(attribute, attribute2 Attribute) *MultiIndex {
	// Consistently map to the right index no matter what order they are called
	if attribute > attribute2 {
		attribute, attribute2 = attribute2, attribute
	}

	if attribute2 == NonExistingAttribute {
		panic("Cannot create multi-index with non-existing attribute")
	}

	indexkey := AttributePair{attribute, attribute2}
	os.indexlock.RLock()
	index, found := os.multiindexes[indexkey]
	os.indexlock.RUnlock()
	if found {
		return index
	}

	for {
		os.indexlock.Lock()
		if index, found := os.multiindexes[indexkey]; found {
			os.indexlock.Unlock()
			return index
		}
		if !os.claimIndexBuild(indexkey) {
			continue
		}
		index := &MultiIndex{}
		os.refreshMultiIndex(attribute, attribute2, index)
		os.indexlock.Lock()
		os.multiindexes[indexkey] = index
		os.finishIndexBuild(indexkey)
		return index
	}
}

func (os *IndexedGraph) refreshIndex(attribute Attribute, index *Index) {
	index.init()
	os.buildIndex(func(o *Node, add func(hash uint64, key, key2 AttributeValue)) {
		o.Attr(attribute).Iterate(func(value AttributeValue) bool {
			add(indexHash(value), value, AttributeValue{})
			return true
		})
	}, func(shard int, r indexRecord) {
		index.shards[shard].entry(r.key, r.hash).add(r.node, false)
	})
}

func (os *IndexedGraph) refreshMultiIndex(attribute, attribute2 Attribute, index *MultiIndex) {
	index.init()
	os.buildIndex(func(o *Node, add func(hash uint64, key, key2 AttributeValue)) {
		if !o.HasAttr(attribute) || !o.HasAttr(attribute2) {
			return
		}
		o.Attr(attribute).Iterate(func(value AttributeValue) bool {
			o.Attr(attribute2).Iterate(func(value2 AttributeValue) bool {
				add(multiIndexHash(value, value2), value, value2)
				return true
			})
			return true
		})
	}, func(shard int, r indexRecord) {
		index.shards[shard].entry(r.key, r.key2, r.hash).add(r.node, false)
	})
}

type indexRecord struct {
	hash      uint64
	key, key2 AttributeValue
	node      *Node
}

// buildIndex fills an empty index from every node, in graph order within
// each key. A large graph is read in ranges on several workers, each range's
// records kept by index shard; then each worker inserts the records of the
// shards it owns, range by range, so it needs no locks and keeps the order.
func (os *IndexedGraph) buildIndex(read func(o *Node, add func(hash uint64, key, key2 AttributeValue)), insert func(shard int, r indexRecord)) {
	os.nodeMutex.RLock()
	defer os.nodeMutex.RUnlock()
	nodes := os.nodes
	const parallelFrom = 1 << 16
	if len(nodes) < parallelFrom {
		for _, o := range nodes {
			read(o, func(hash uint64, key, key2 AttributeValue) {
				insert(indexShardOf(hash), indexRecord{hash, key, key2, o})
			})
		}
		return
	}
	workers := runtime.GOMAXPROCS(0)
	ranges := workers * 4
	size := (len(nodes) + ranges - 1) / ranges
	records := make([][indexShardCount][]indexRecord, ranges)
	var wg sync.WaitGroup
	var next atomic.Int64
	for range workers {
		wg.Go(func() {
			for r := int(next.Add(1) - 1); r < ranges; r = int(next.Add(1) - 1) {
				for _, o := range nodes[min(len(nodes), r*size):min(len(nodes), (r+1)*size)] {
					read(o, func(hash uint64, key, key2 AttributeValue) {
						shard := indexShardOf(hash)
						records[r][shard] = append(records[r][shard], indexRecord{hash, key, key2, o})
					})
				}
			}
		})
	}
	wg.Wait()
	for w := range workers {
		wg.Go(func() {
			for shard := w; shard < indexShardCount; shard += workers {
				for r := range records {
					for _, record := range records[r][shard] {
						insert(shard, record)
					}
				}
			}
		})
	}
	wg.Wait()
}

func (os *IndexedGraph) setRoot(ro *Node) {
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

func (os *IndexedGraph) reindexObject(o *Node, isnew bool) {
	// Single attribute indexes
	os.indexlock.RLock()
	for i, index := range os.indexes {
		if index != nil {
			attribute := Attribute(i)
			o.AttrRendered(attribute).Iterate(func(value AttributeValue) bool {
				indexval := value

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
			o.Attr(attribute2).Iterate(func(value2 AttributeValue) bool {
				index.Add(value, value2, o, !isnew)

				return true
			})
			return true
		})
	}
	os.indexlock.RUnlock()
}

// AttributeValueToIndex is kept for callers; indexes match strings ignoring
// case themselves, so values are used as they are.
func AttributeValueToIndex(value AttributeValue) AttributeValue {
	return value
}

func (os *IndexedGraph) Filter(evaluate func(o *Node) bool) *IndexedGraph {
	result := NewIndexedGraph()

	os.IterateStable(func(n *Node) bool {
		if evaluate(n) {
			result.add(n)
		}
		return true
	})
	return result
}

// NewResultGraph returns a graph holding nodes of another graph, such as the
// results of a query. The nodes are shared, not copied, and a node listed
// more than once is held once. It has no edges.
func NewResultGraph(nodes ...NodeSlice) *IndexedGraph {
	result := NewIndexedGraph()
	for _, ns := range nodes {
		ns.Iterate(func(n *Node) bool {
			if !result.Contains(n) {
				result.add(n)
			}
			return true
		})
	}
	return result
}

func (os *IndexedGraph) addNew(flexinit ...any) *Node {
	o := NewNode(flexinit...)
	if os.DefaultValues != nil {
		o.setFlex(os.DefaultValues...)
	}
	os.add(o)
	return o
}

func (os *IndexedGraph) add(obs *Node) {
	os.nodeMutex.Lock() // This is due to FindOrAdd consistency
	os.addUnlocked(obs)
	os.nodeMutex.Unlock()
}

func (os *IndexedGraph) Contains(o *Node) bool {
	_, found := os.nodeLookup.Load(o)
	return found
}

func (os *IndexedGraph) indexToNode(id NodeIndex) (*Node, bool) {
	if len(os.nodes) <= int(id) {
		return nil, false
	}
	return os.nodes[id], true
}

func (os *IndexedGraph) nodeToIndex(node *Node) (NodeIndex, bool) {
	// Nodes can belong to multiple graphs. An index belongs to this graph,
	// never to the shared node itself.
	return os.nodeLookup.Load(node)
}

func (os *IndexedGraph) LookupNodeByID(id NodeID) (*Node, bool) {
	if id == InvalidNodeID {
		return nil, false
	}
	os.idMutex.RLock()
	if os.idLookup != nil && os.idVersion == os.nodesVersion.Load() {
		n, found := os.idLookup[id]
		os.idMutex.RUnlock()
		return n, found
	}
	os.idMutex.RUnlock()

	os.idMutex.Lock()
	defer os.idMutex.Unlock()
	os.nodeMutex.RLock()
	if version := os.nodesVersion.Load(); os.idLookup == nil || os.idVersion != version {
		os.idLookup = make(map[NodeID]*Node, len(os.nodes))
		for _, n := range os.nodes {
			if n.id != InvalidNodeID {
				os.idLookup[n.id] = n
			}
		}
		os.idVersion = version
	}
	os.nodeMutex.RUnlock()
	n, found := os.idLookup[id]
	return n, found
}

func (os *IndexedGraph) addUnlocked(newNode *Node) {
	os.addUnlockedWith(newNode, true)
}

func (os *IndexedGraph) addUnlockedWith(newNode *Node, defaults bool) {
	index := NodeIndex(len(os.nodes))
	if _, found := os.nodeLookup.LoadOrStore(newNode, index); !found {
		if defaults && os.DefaultValues != nil {
			newNode.setFlex(os.DefaultValues...)
		}
		os.nodes = append(os.nodes, newNode)
		os.nodesVersion.Add(1)
		os.reindexObject(newNode, true)
		os.typecount[newNode.Type()]++
	} else {
		panic("Node already exists in graph, so we can't add it")
	}
}

// addCollection appends new nodes in order and returns the position of the
// first. Their default values were given where they were built. Lookups
// and indexes are filled on several workers for a large collection.
func (os *IndexedGraph) addCollection(nodes []*Node) NodeIndex {
	os.nodeMutex.Lock()
	defer os.nodeMutex.Unlock()
	base := NodeIndex(len(os.nodes))
	os.nodes = append(os.nodes, nodes...)
	os.nodesVersion.Add(1)
	add := func(i int) {
		n := nodes[i]
		if _, found := os.nodeLookup.LoadOrStore(n, base+NodeIndex(i)); found {
			panic("Node already exists in graph, so we can't add it")
		}
		os.reindexObject(n, true)
	}
	const perWorker = 256
	if workers := min(runtime.GOMAXPROCS(0), len(nodes)/perWorker); workers > 1 {
		var wg sync.WaitGroup
		for w := range workers {
			wg.Go(func() {
				for i := w; i < len(nodes); i += workers {
					add(i)
				}
			})
		}
		wg.Wait()
	} else {
		for i := range nodes {
			add(i)
		}
	}
	for _, n := range nodes {
		os.typecount[n.Type()]++
	}
	return base
}

func (os *IndexedGraph) addRelaxed(newNode *Node) {
	os.nodeMutex.Lock()
	index := NodeIndex(len(os.nodes))
	if _, found := os.nodeLookup.LoadOrStore(newNode, index); !found {
		if os.DefaultValues != nil {
			newNode.setFlex(os.DefaultValues...)
		}
		os.nodes = append(os.nodes, newNode)
		os.nodesVersion.Add(1)
		os.reindexObject(newNode, true)
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
	os.IterateStable(func(o *Node) bool {
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
	os.nodeMutex.RLock()
	nodes := slices.Clone(os.nodes)
	os.nodeMutex.RUnlock()

	for _, n := range nodes {
		if !each(n) {
			return
		}
	}
}

// IterateStable visits the current node slice without cloning it.
// The callback must not add or remove nodes from this graph or call methods
// that require taking nodeMutex for writing.
func (os *IndexedGraph) IterateStable(each func(o *Node) bool) {
	os.nodeMutex.RLock()
	defer os.nodeMutex.RUnlock()

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
	os.nodeMutex.RLock()
	nodes := slices.Clone(os.nodes)
	os.nodeMutex.RUnlock()

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
	for _, o := range nodes {
		if i&0x3ff == 0 && stop.Load() {
			ui.Debug().Msg("Aborting parallel iterator for Objects")
			break
		}
		queue <- o
		i++
	}

	close(queue)
	wg.Wait()
}

// IterateParallelStable visits the current node slice in parallel without cloning it.
// The callback must not add or remove nodes from this graph or call methods
// that require taking nodeMutex for writing.
func (os *IndexedGraph) IterateParallelStable(each func(o *Node) bool, parallelFuncs int) {
	if parallelFuncs == 0 {
		parallelFuncs = runtime.NumCPU()
	}
	os.nodeMutex.RLock()
	defer os.nodeMutex.RUnlock()

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
	for _, o := range os.nodes {
		if i&0x3ff == 0 && stop.Load() {
			ui.Debug().Msg("Aborting parallel iterator for Objects")
			break
		}
		queue <- o
		i++
	}

	close(queue)
	wg.Wait()
}

func (os *IndexedGraph) findOrAdd(attribute Attribute, value AttributeValue, flexinit ...any) (*Node, bool) {
	o, found := os.findMultiOrAdd(attribute, value, func() *Node {
		return NewNode(append(flexinit, attribute, value)...)
	})
	return o.First(), found
}

func (os *IndexedGraph) Find(attribute Attribute, value AttributeValue) (o *Node, found bool) {
	v, found := os.findMultiOrAdd(attribute, value, nil)
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

func (os *IndexedGraph) findTwoOrAdd(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue, flexinit ...any) (o *Node, found bool) {
	results, found := os.findTwoMultiOrAdd(attribute, value, attribute2, value2, func() *Node {
		return NewNode(append(flexinit, attribute, value, attribute2, value2)...)
	})
	if !found {
		return results.First(), false
	}
	return results.First(), results.Len() == 1
}

func (os *IndexedGraph) FindTwoMulti(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue) (o NodeSlice, found bool) {
	return os.findTwoMultiOrAdd(attribute, value, attribute2, value2, nil)
}

func (os *IndexedGraph) FindMulti(attribute Attribute, value AttributeValue) (NodeSlice, bool) {
	return os.findTwoMultiOrAdd(attribute, value, NonExistingAttribute, AttributeValue{}, nil)
}

func (os *IndexedGraph) findMultiOrAdd(attribute Attribute, value AttributeValue, addifnotfound func() *Node) (NodeSlice, bool) {
	return os.findTwoMultiOrAdd(attribute, value, NonExistingAttribute, AttributeValue{}, addifnotfound)
}

func (os *IndexedGraph) findTwoMultiOrAdd(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue, addifnotfound func() *Node) (NodeSlice, bool) {
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
	var singleIndex *Index
	var multiIndex *MultiIndex
	if attribute2 == NonExistingAttribute {
		singleIndex = os.GetIndex(attribute)
	} else {
		multiIndex = os.GetMultiIndex(attribute, attribute2)
	}

	os.nodeMutex.Lock() // Prevent anyone from adding to objects while we're searching

	if attribute2 == NonExistingAttribute {
		// Lookup by one attribute
		matches, found := singleIndex.Lookup(value)
		if found {
			os.nodeMutex.Unlock()
			return matches, found
		}
	} else {
		// Lookup by two attributes
		matches, found := multiIndex.Lookup(value, value2)
		if found {
			os.nodeMutex.Unlock()
			return matches, found
		}
	}

	// Create new object
	no := addifnotfound()
	if no != nil {
		if len(os.DefaultValues) > 0 {
			no.setFlex(os.DefaultValues...)
		}
		os.addUnlocked(no)
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

func (os *IndexedGraph) findOrAddAdjacentSID(s windowssecurity.SID, r *Node, flexinit ...any) *Node {
	sidobject, _ := os.findOrAddAdjacentSIDFound(s, r, flexinit...)
	return sidobject
}

// findSIDWithScope finds the node for a SID within one domain or machine.
// When a scope already holds several nodes for the SID, it returns the one
// added first, so lookups agree and never add yet another node.
func (os *IndexedGraph) findSIDWithScope(scope Attribute, scopeValue AttributeValue, sidValue AttributeValue) (*Node, bool) {
	nodes, found := os.GetMultiIndex(ObjectSid, scope).Lookup(sidValue, scopeValue)
	if !found || nodes.Len() == 0 {
		return nil, false
	}
	var first *Node
	var firstIndex NodeIndex
	nodes.Iterate(func(n *Node) bool {
		if index, ok := os.nodeLookup.Load(n); ok && (first == nil || index < firstIndex) {
			first, firstIndex = n, index
		}
		return true
	})
	return first, first != nil
}

func (os *IndexedGraph) FindAdjacentSID(s windowssecurity.SID, relativeTo *Node) (*Node, bool) {
	return os.findAdjacentSID(s, relativeTo)
}

func (os *IndexedGraph) findAdjacentSID(s windowssecurity.SID, relativeTo *Node) (*Node, bool) {
	sidValue := NVSID(s)
	if relativeTo == nil {
		return os.Find(ObjectSid, sidValue)
	}

	relativeType := relativeTo.Type()
	relativeSID := relativeTo.SID()
	domainContext := relativeTo.OneAttr(DomainContext)
	dataSource := relativeTo.OneAttr(DataSource)

	if relativeType == NodeTypeMachine && !dataSource.IsNil() && s.StripRID() == relativeSID {
		return os.FindTwo(ObjectSid, sidValue, DataSource, dataSource)
	}

	if s.Component(2) == 21 && s.Component(3) != 0 {
		result, found := os.FindMulti(ObjectSid, sidValue)
		if !found || result.Len() != 1 {
			return nil, false
		}
		return result.First(), true
	}

	if !domainContext.IsNil() {
		if o, found := os.findSIDWithScope(DomainContext, domainContext, sidValue); found {
			return o, true
		}
	}

	if !dataSource.IsNil() {
		if o, found := os.findSIDWithScope(DataSource, dataSource, sidValue); found {
			return o, true
		}
	}

	// Builtin and well-known SIDs mean a different principal in every
	// domain and on every machine, so a scoped lookup never falls back to
	// another scope's node.
	if !domainContext.IsNil() || !dataSource.IsNil() {
		return nil, false
	}
	return os.Find(ObjectSid, sidValue)
}

func (os *IndexedGraph) findOrAddAdjacentSIDFound(s windowssecurity.SID, relativeTo *Node, flexinit ...any) (*Node, bool) {
	if found, ok := os.findAdjacentSID(s, relativeTo); ok {
		return found, true
	}

	sidValue := NVSID(s)
	if relativeTo == nil {
		return os.findOrAdd(ObjectSid, sidValue)
	}

	dataSource := relativeTo.OneAttr(DataSource)
	if relativeTo.Type() == NodeTypeMachine && !dataSource.IsNil() && s.StripRID() == relativeTo.SID() {
		return os.findTwoOrAdd(ObjectSid, sidValue, DataSource, dataSource)
	}

	if s.Component(2) == 21 && s.Component(3) != 0 {
		result, found := os.findMultiOrAdd(ObjectSid, sidValue, func() *Node {
			no := NewNode(
				ObjectSid, sidValue,
			)
			no.setFlex(flexinit...)
			return no
		})
		return result.First(), found
	}

	domainContext := relativeTo.OneAttr(DomainContext)
	if domainContext.IsNil() && dataSource.IsNil() {
		return os.findOrAdd(ObjectSid, sidValue)
	}
	// Not in this scope yet: add it to the scope, even if another domain or
	// machine has a node for the same SID. flexinit is not applied here, as
	// before; attributes such as a shared DN would merge scopes again.
	no := NewNode(
		IgnoreBlanks,
		ObjectSid, sidValue,
		DomainContext, domainContext,
		DataSource, dataSource,
	)
	os.add(no)
	return no, false
}

func (os *IndexedGraph) FindGUID(g uuid.UUID) (o *Node, found bool) {
	return os.Find(ObjectGUID, NV(g))
}
