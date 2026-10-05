package engine

import (
	"cmp"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/lkarlslund/adalanche/modules/util"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// Tx is a transaction on a graph. Reads see the graph as it was when the
// transaction began, plus the transaction's own new nodes; writes are
// recorded and only change the graph when the transaction is committed.
// A graph is not changed while transactions read it: transactions that run
// together read the same graph, and their changes are committed afterwards
// in a fixed order.
//
// A Tx is used by one goroutine at a time.
type Tx struct {
	g        *IndexedGraph
	name     string
	readOnly bool // no writes allowed
	noReads  bool // write-only: no reads of the graph allowed
	origin   *Tx  // the transaction this one was forked from, if any

	// A load transaction (BeginLoad) reads only what it staged itself, and
	// its writes to nodes that already exist are merged in as unions, so
	// loaders committing in any order give the same graph.
	load       bool
	collection bool               // a load of one self-contained collection: identities resolve only within it
	created    map[*Node]struct{} // nodes this transaction's commit added, for a collection
	loader     string             // the loader's name, its dataLoader value; set, the transaction sees only that loader's nodes
	loaderNV   AttributeValue
	loadRoot   *Node // the loader's root node
	loadValues []any // default values for nodes the loader creates

	pending []*pendingNode               // in creation order, for a deterministic commit
	byNode  map[*Node]*pendingNode       // base nodes this transaction writes to
	views   map[*Node]*pendingNode       // staged nodes and shadows, by their view
	byKey   map[pendingKey]*pendingNode  // staged nodes by identity
	staged  map[Attribute]*Index         // staged nodes by attribute value, for Find
	edges   map[[2]endpoint]*pendingEdge // edge writes by node pair
	edgeSeq []*pendingEdge               // edge writes in order
}

type pendingKind uint8

const (
	pendingBase  pendingKind = iota // a node already in the graph
	pendingNew                      // a new node with no identity
	pendingKeyed                    // find or add by one or two attribute values
	pendingSID                      // find or add a SID relative to another node
)

type pendingKey struct {
	attr1, attr2   Attribute
	value1, value2 AttributeValue
	sid            windowssecurity.SID
	scope          AttributeValue
	scopeAttr      Attribute
}

type pendingNode struct {
	kind pendingKind
	base *Node // pendingBase: the node in the graph
	view *Node // what reads through the transaction see; nil for an untouched base node

	// identity for pendingKeyed and pendingSID
	key        pendingKey
	init       []any    // attributes set only when the node is created
	relativeTo endpoint // pendingSID: the node the SID is relative to

	ops []nodeOp // writes, replayed on the resolved node at commit

	resolved *Node // set at commit
	existed  bool  // the node was already in the graph when resolved
	adopt    *Node // pendingKeyed from AddIdentified: the node to add when the identity is new
}

type nodeOpKind uint8

const (
	nodeOpSet nodeOpKind = iota
	nodeOpAdd
	nodeOpClear
	nodeOpTag
	nodeOpChildOf
	nodeOpSetMany // attrs[i] is set to values[i]
)

type nodeOp struct {
	kind   nodeOpKind
	attr   Attribute
	values AttributeValues
	attrs  []Attribute // nodeOpSetMany
	tag    string
	parent endpoint
}

// endpoint is a node as a transaction refers to it: either a node of the
// graph that the transaction does not write to, or a pending node.
type endpoint struct {
	node *Node
	p    *pendingNode
}

type pendingEdge struct {
	from, to   endpoint
	sources    []pendingSource // why, see EdgeBecause
	set        EdgeBitmap // bits to set
	clear      EdgeBitmap // bits to clear
	replace    bool       // replace the existing bitmap with set
	force      bool       // keep edges between nodes for the same SID
	unfiltered bool       // set as a bitmap: no filtering at all, like IndexedGraph.SetEdge
}

// pendingSource is a cause staged with an edge.
type pendingSource struct {
	edge   Edge
	kind   SourceKind
	about  endpoint
	detail string
}

// NodeRef is anything a transaction can resolve to a node: a node read from
// the transaction, or a handle from it.
type NodeRef interface {
	endpointIn(tx *Tx) endpoint
}

func (o *Node) endpointIn(tx *Tx) endpoint {
	if p, found := tx.views[o]; found {
		return endpoint{p: p}
	}
	if p, found := tx.byNode[o]; found {
		return endpoint{p: p}
	}
	return endpoint{node: o}
}

func (n TxNode) endpointIn(tx *Tx) endpoint {
	if n.tx != tx {
		panic("node handle used with another transaction")
	}
	if n.p == nil {
		return n.node.endpointIn(tx)
	}
	return endpoint{p: n.p}
}

// Begin starts a transaction that reads and writes the graph.
func (g *IndexedGraph) Begin(name string) *Tx {
	return &Tx{
		g:      g,
		name:   name,
		byNode: map[*Node]*pendingNode{},
		views:  map[*Node]*pendingNode{},
		byKey:  map[pendingKey]*pendingNode{},
		edges:  map[[2]endpoint]*pendingEdge{},
	}
}

// defaultValues are the values new nodes get: the loader's for a load
// transaction, otherwise the graph's.
func (tx *Tx) defaultValues() []any {
	if tx.loader != "" {
		return tx.loadValues
	}
	return tx.g.DefaultValues
}

// BeginLoad starts a load transaction for a loader: lookups see only what
// the transaction staged, new nodes get values (such as the loader's name),
// root is the loader's root node, and writes onto nodes another loader
// already committed are merged in as unions.
func (g *IndexedGraph) BeginLoad(name, loader string, root *Node) *Tx {
	tx := g.Begin(name)
	tx.load, tx.loadRoot = true, root
	tx.scopeTo(loader)
	return tx
}

// scopeTo limits a transaction to one loader's nodes: iteration and lookups
// see only nodes with that data loader, nodes it creates get it, and
// identities resolve among them. Loader-phase processors run this way, as if
// each loader had a graph of its own.
func (tx *Tx) scopeTo(loader string) {
	tx.loader, tx.loaderNV, tx.loadValues = loader, NV(loader), []any{DataLoader, NV(loader)}
}

func (tx *Tx) inScope(n *Node) bool {
	return tx.loader == "" || n.HasAttrValue(DataLoader, tx.loaderNV)
}

func (tx *Tx) scoped(nodes NodeSlice) NodeSlice {
	if tx.loader == "" {
		return nodes
	}
	var result NodeSlice
	nodes.Iterate(func(n *Node) bool {
		if tx.inScope(n) {
			result.Add(n)
		}
		return true
	})
	return result
}

// BeginWriteOnly starts a transaction that only writes, such as a loader:
// it states what it found and never depends on what the graph holds.
func (g *IndexedGraph) BeginWriteOnly(name string) *Tx {
	tx := g.Begin(name)
	tx.noReads = true
	return tx
}

// BeginReadOnly starts a transaction that only reads.
func (g *IndexedGraph) BeginReadOnly(name string) *Tx {
	tx := g.Begin(name)
	tx.readOnly = true
	return tx
}

func (tx *Tx) Name() string { return tx.name }

func (tx *Tx) checkRead() {
	if tx.noReads {
		panic("transaction " + tx.name + " is write-only")
	}
}

func (tx *Tx) checkWrite() {
	if tx.readOnly {
		panic("transaction " + tx.name + " is read-only")
	}
}

// HasWrites reports whether committing the transaction would change anything.
func (tx *Tx) HasWrites() bool {
	return len(tx.pending) > 0 || len(tx.edgeSeq) > 0
}

// --- Handles -----------------------------------------------------------------

// TxNode is a node as a transaction writes it. Its modifiers record writes
// in the transaction; nothing changes in the graph until commit.
type TxNode struct {
	tx   *Tx
	node *Node        // a node of the graph the transaction has not written to yet
	p    *pendingNode // otherwise
}

// Node returns a handle for writing to a node read from the graph.
func (tx *Tx) Node(o *Node) TxNode {
	ep := o.endpointIn(tx)
	if ep.p != nil {
		return TxNode{tx: tx, p: ep.p}
	}
	return TxNode{tx: tx, node: o}
}

// pending returns the handle's pending node, creating it for a node of the
// graph on its first write.
func (n *TxNode) pending() *pendingNode {
	if n.p == nil {
		if p, found := n.tx.byNode[n.node]; found {
			n.p = p
		} else {
			n.p = &pendingNode{kind: pendingBase, base: n.node}
			n.tx.byNode[n.node] = n.p
			n.tx.pending = append(n.tx.pending, n.p)
		}
	}
	return n.p
}

// Valid reports whether the handle refers to a node.
func (n TxNode) Valid() bool { return n.p != nil || n.node != nil }

// Node returns the node as the transaction sees it, including the
// transaction's own writes. Once the transaction is committed, it is the
// graph's node.
func (n TxNode) Node() *Node {
	if n.p == nil {
		if p, found := n.tx.byNode[n.node]; found {
			n.p = p
		} else {
			return n.node
		}
	}
	p := n.p
	if p.resolved != nil {
		return p.resolved
	}
	if p.view != nil {
		return p.view
	}
	if p.kind == pendingBase && len(p.ops) == 0 {
		return p.base
	}
	// A base node read after writing to it: a private copy with the writes.
	view := p.base.shadowCopy()
	for _, op := range p.ops {
		applyNodeOp(view, op, nil)
	}
	p.view = view
	n.tx.views[view] = p
	return view
}

func (n TxNode) record(op nodeOp) TxNode {
	n.tx.checkWrite()
	p := n.pending()
	// A new node is its own staged copy, so only parent links (which
	// need the other node resolved) wait for the commit.
	if p.kind != pendingNew || op.kind == nodeOpChildOf {
		p.ops = append(p.ops, op)
	}
	if p.view != nil {
		applyNodeOp(p.view, op, nil)
		if p.kind != pendingBase {
			n.tx.indexStaged(p, op)
		}
	}
	return n
}

func (n TxNode) Set(a Attribute, values ...AttributeValue) TxNode {
	return n.record(nodeOp{kind: nodeOpSet, attr: a, values: slices.Clone(AttributeValues(values))})
}

// SetMany sets each attribute in attrs to the value at the same position in
// values, as one write: for computed results with many attributes per node.
// The transaction keeps both slices; the caller must not change them.
func (n TxNode) SetMany(attrs []Attribute, values []AttributeValue) TxNode {
	if len(attrs) != len(values) {
		panic("SetMany needs one value per attribute")
	}
	return n.record(nodeOp{kind: nodeOpSetMany, attrs: attrs, values: values})
}

func (n TxNode) Add(a Attribute, values ...AttributeValue) TxNode {
	return n.record(nodeOp{kind: nodeOpAdd, attr: a, values: slices.Clone(AttributeValues(values))})
}

func (n TxNode) Clear(a Attribute) TxNode {
	return n.record(nodeOp{kind: nodeOpClear, attr: a})
}

func (n TxNode) Tag(tag string) TxNode {
	return n.record(nodeOp{kind: nodeOpTag, tag: tag})
}

// SetFlex sets attributes given as alternating attributes and values, like
// NewNode.
func (n TxNode) SetFlex(flexinit ...any) TxNode {
	for _, patch := range expandFlexInit(flexinit...) {
		n.record(nodeOp{kind: nodeOpSet, attr: patch.attr, values: patch.values})
	}
	return n
}

// ChildOf makes the node a child of parent, unless it already has a parent.
func (n TxNode) ChildOf(parent NodeRef) TxNode {
	return n.record(nodeOp{kind: nodeOpChildOf, parent: parent.endpointIn(n.tx)})
}

// EdgeTo adds an edge from this node to another.
func (n TxNode) EdgeTo(to NodeRef, edge Edge) TxNode {
	n.tx.EdgeTo(n, to, edge)
	return n
}

// EdgeBecause adds an edge from this node to another and records why.
func (n TxNode) EdgeBecause(to NodeRef, edge Edge, source Source) TxNode {
	n.tx.EdgeBecause(n, to, edge, source)
	return n
}

// SID is the node's SID as the transaction sees it.
func (n TxNode) SID() windowssecurity.SID { return n.Node().SID() }

// --- New nodes ----------------------------------------------------------------

func (tx *Tx) stage(p *pendingNode, view *Node) TxNode {
	tx.checkWrite()
	p.view = view
	tx.views[view] = p
	tx.pending = append(tx.pending, p)
	for a := range tx.staged {
		tx.indexStagedValues(p, a, view.Attr(a))
	}
	return TxNode{tx: tx, p: p}
}

// AddNew stages a new node with no identity: it is always added.
func (tx *Tx) AddNew(flexinit ...any) TxNode {
	view := NewNode(flexinit...)
	if d := tx.defaultValues(); d != nil {
		view.setFlex(d...)
	}
	return tx.stage(&pendingNode{kind: pendingNew}, view)
}

// Add stages a node built outside the graph, such as by a loader. It is
// always added.
func (tx *Tx) Add(o *Node) TxNode {
	if d := tx.defaultValues(); d != nil {
		o.setFlex(d...)
	}
	return tx.stage(&pendingNode{kind: pendingNew}, o)
}

// AddIdentified stages a node built outside the graph under an identity: the
// value it has for key. Within the transaction, and at commit against the
// graph, it becomes one node with any other holding that value; in a load
// transaction its values are then merged in as unions. A node without a
// value for key is staged as a new node.
func (tx *Tx) AddIdentified(o *Node, key Attribute) TxNode {
	value := o.OneAttr(key)
	if value.IsNil() {
		return tx.Add(o)
	}
	var flex []any
	o.AttrIterator(func(attr Attribute, values AttributeValues) bool {
		flex = append(flex, attr, values)
		return true
	})
	k := pendingKey{attr1: key, value1: value, attr2: NonExistingAttribute}
	if p, found := tx.byKey[k]; found {
		return TxNode{tx: tx, p: p}.SetFlex(flex...)
	}
	if d := tx.defaultValues(); d != nil {
		o.setFlex(d...)
		flex = append(flex, d...)
	}
	p := &pendingNode{kind: pendingKeyed, key: k, init: flex, adopt: o}
	tx.byKey[k] = p
	return tx.stage(p, o)
}

// FindOrAdd returns the node with attribute set to value, or stages a new
// one with flexinit when there is none. The attributes in flexinit apply
// only when the node is created.
func (tx *Tx) FindOrAdd(attribute Attribute, value AttributeValue, flexinit ...any) (TxNode, bool) {
	return tx.findOrAddKeyed(attribute, value, NonExistingAttribute, AttributeValue{}, flexinit)
}

// FindTwoOrAdd is FindOrAdd keyed by two attribute values.
func (tx *Tx) FindTwoOrAdd(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue, flexinit ...any) (TxNode, bool) {
	return tx.findOrAddKeyed(attribute, value, attribute2, value2, flexinit)
}

func (tx *Tx) findOrAddKeyed(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue, flexinit []any) (TxNode, bool) {
	if attribute2 != NonExistingAttribute && attribute > attribute2 {
		attribute, attribute2 = attribute2, attribute
		value, value2 = value2, value
	}
	if !tx.noReads && !tx.load {
		var found NodeSlice
		var ok bool
		if attribute2 == NonExistingAttribute {
			found, ok = tx.FindMulti(attribute, value)
		} else {
			found, ok = tx.FindTwoMulti(attribute, value, attribute2, value2)
		}
		if ok && found.Len() > 0 {
			return tx.handleFor(found.First()), true
		}
	}
	key := pendingKey{attr1: attribute, value1: value, attr2: attribute2, value2: value2}
	if p, found := tx.byKey[key]; found {
		return TxNode{tx: tx, p: p}, true
	}
	init := slices.Clone(flexinit)
	if attribute2 != NonExistingAttribute {
		init = append(init, attribute, value, attribute2, value2)
	} else {
		init = append(init, attribute, value)
	}
	if tx.loader != "" {
		init = append(init, tx.loadValues...)
	}
	view := NewNode(init...)
	if d := tx.defaultValues(); d != nil {
		view.setFlex(d...)
	}
	p := &pendingNode{kind: pendingKeyed, key: key, init: init}
	tx.byKey[key] = p
	return tx.stage(p, view), false
}

// FindOrAddAdjacentSID returns the node for a SID as seen from relativeTo
// (see IndexedGraph.FindOrAddAdjacentSID), staging it when the graph has
// none.
func (tx *Tx) FindOrAddAdjacentSID(s windowssecurity.SID, relativeTo NodeRef, flexinit ...any) TxNode {
	n, _ := tx.FindOrAddAdjacentSIDFound(s, relativeTo, flexinit...)
	return n
}

func (tx *Tx) FindOrAddAdjacentSIDFound(s windowssecurity.SID, relativeTo NodeRef, flexinit ...any) (TxNode, bool) {
	var rel endpoint
	var relNode *Node
	if relativeTo != nil {
		rel = relativeTo.endpointIn(tx)
		relNode = tx.endpointView(rel)
	}
	if !tx.noReads && !tx.load && (relNode == nil || rel.p == nil || rel.p.kind == pendingBase) {
		if found, ok := tx.baseAdjacentSID(s, relNode); ok {
			return tx.handleFor(found), true
		}
	}
	key := sidKey(s, relNode)
	if p, found := tx.byKey[key]; found {
		return TxNode{tx: tx, p: p}, true
	}
	if staged, found := tx.findStagedAdjacentSID(s, relNode); found {
		return tx.handleFor(staged), true
	}
	view := NewNode(IgnoreBlanks, ObjectSid, NVSID(s), key.scopeAttr, key.scope)
	view.setFlex(flexinit...)
	if d := tx.defaultValues(); d != nil {
		view.setFlex(d...)
	}
	p := &pendingNode{kind: pendingSID, key: key, init: slices.Clone(flexinit), relativeTo: rel}
	tx.byKey[key] = p
	return tx.stage(p, view), false
}

// sidKey is the scope a SID is staged in, following the scopes of
// IndexedGraph.FindOrAddAdjacentSIDFound, so two references to the same
// principal in one transaction share a node.
func sidKey(s windowssecurity.SID, relativeTo *Node) pendingKey {
	key := pendingKey{sid: s}
	if relativeTo == nil {
		return key
	}
	dataSource := relativeTo.OneAttr(DataSource)
	switch {
	case relativeTo.Type() == NodeTypeMachine && !dataSource.IsNil() && s.StripRID() == relativeTo.SID():
		key.scopeAttr, key.scope = DataSource, dataSource
	case s.Component(2) == 21 && s.Component(3) != 0:
		// account SIDs are global
	default:
		if dc := relativeTo.OneAttr(DomainContext); !dc.IsNil() {
			key.scopeAttr, key.scope = DomainContext, dc
		} else if !dataSource.IsNil() {
			key.scopeAttr, key.scope = DataSource, dataSource
		}
	}
	return key
}

// handleFor returns a handle for a node read through the transaction.
func (tx *Tx) handleFor(o *Node) TxNode {
	return tx.Node(o)
}

func (tx *Tx) endpointView(ep endpoint) *Node {
	if ep.p == nil {
		return ep.node
	}
	return TxNode{tx: tx, p: ep.p}.Node()
}

// --- Staged lookups -------------------------------------------------------------

func (tx *Tx) indexStaged(p *pendingNode, op nodeOp) {
	switch op.kind {
	case nodeOpSet, nodeOpAdd:
		tx.indexStagedValues(p, op.attr, op.values)
	case nodeOpSetMany:
		for i, a := range op.attrs {
			tx.indexStagedValues(p, a, op.values[i:i+1])
		}
	case nodeOpTag:
		tx.indexStagedValues(p, Tag, AttributeValues{NV(op.tag)})
	}
}

// indexStagedValues keeps the staged index for an attribute up to date, once
// a lookup by that attribute has built it.
func (tx *Tx) indexStagedValues(p *pendingNode, a Attribute, values AttributeValues) {
	index := tx.staged[a]
	if index == nil {
		return
	}
	for _, v := range values {
		index.Add(v, p.view, true)
	}
}

// stagedLookup finds staged nodes by an attribute value. The index for an
// attribute is built on its first lookup, so a transaction that stages many
// nodes and never looks them up pays nothing.
func (tx *Tx) stagedLookup(a Attribute, v AttributeValue) NodeSlice {
	index := tx.staged[a]
	if index == nil {
		if len(tx.views) == 0 {
			return NodeSlice{}
		}
		if tx.staged == nil {
			tx.staged = map[Attribute]*Index{}
		}
		index = &Index{}
		index.init()
		for _, p := range tx.pending {
			if p.kind == pendingBase || p.view == nil {
				continue
			}
			p.view.Attr(a).Iterate(func(value AttributeValue) bool {
				index.Add(value, p.view, true)
				return true
			})
		}
		tx.staged[a] = index
	}
	if nodes, found := index.Lookup(v); found {
		return nodes
	}
	return NodeSlice{}
}

// --- Reads ----------------------------------------------------------------------

func (tx *Tx) Graph() *IndexedGraph { return tx.g }

func (tx *Tx) Root() *Node {
	tx.checkRead()
	if tx.loadRoot != nil {
		return tx.loadRoot
	}
	return tx.g.Root()
}

func (tx *Tx) Order() int { tx.checkRead(); return tx.g.Order() }

// Iterate visits the nodes of the graph as it was when the transaction
// began; nodes the transaction adds are not visited.
func (tx *Tx) Iterate(each func(o *Node) bool) {
	tx.checkRead()
	if tx.loader != "" {
		for _, o := range tx.scopeNodes() {
			if !each(o) {
				return
			}
		}
		return
	}
	tx.g.IterateStable(each)
}

// IterateParallel is Iterate with several goroutines. The callback must not
// write to the transaction; use Fork for parallel writes.
func (tx *Tx) IterateParallel(each func(o *Node) bool, parallelFuncs int) {
	tx.checkRead()
	if tx.loader != "" {
		nodes := tx.scopeNodes()
		if parallelFuncs == 0 {
			parallelFuncs = runtime.NumCPU()
		}
		var next atomic.Int64
		var stop atomic.Bool
		var wg sync.WaitGroup
		for range parallelFuncs {
			wg.Go(func() {
				for !stop.Load() {
					i := next.Add(1) - 1
					if i >= int64(len(nodes)) {
						return
					}
					if !each(nodes[i]) {
						stop.Store(true)
					}
				}
			})
		}
		wg.Wait()
		return
	}
	tx.g.IterateParallelStable(each, parallelFuncs)
}

// scopeNodes returns the nodes of the transaction's loader in graph order,
// found through the loader index instead of a scan of the whole graph.
func (tx *Tx) scopeNodes() []*Node {
	found, _ := tx.g.FindMulti(DataLoader, tx.loaderNV)
	if found.Len() > tx.g.Order()/2 {
		// Most of the graph: scanning it is cheaper than ordering these.
		result := make([]*Node, 0, found.Len())
		tx.g.IterateStable(func(n *Node) bool {
			if tx.inScope(n) {
				result = append(result, n)
			}
			return true
		})
		return result
	}
	type positioned struct {
		at   NodeIndex
		node *Node
	}
	nodes := make([]positioned, 0, found.Len())
	found.Iterate(func(n *Node) bool {
		// The index can hold values a node no longer has.
		if at, ok := tx.g.nodeToIndex(n); ok && tx.inScope(n) {
			nodes = append(nodes, positioned{at, n})
		}
		return true
	})
	slices.SortFunc(nodes, func(a, b positioned) int { return cmp.Compare(a.at, b.at) })
	result := make([]*Node, len(nodes))
	for i, p := range nodes {
		result[i] = p.node
	}
	return result
}

func (tx *Tx) Find(attribute Attribute, value AttributeValue) (*Node, bool) {
	nodes, _ := tx.FindMulti(attribute, value)
	if nodes.Len() != 1 {
		return nil, false
	}
	return nodes.First(), true
}

func (tx *Tx) FindMulti(attribute Attribute, value AttributeValue) (NodeSlice, bool) {
	tx.checkRead()
	var nodes NodeSlice
	var found bool
	if !tx.load {
		nodes, _ = tx.g.FindMulti(attribute, value)
		nodes = tx.scoped(nodes)
		found = nodes.Len() > 0
	}
	if staged := tx.stagedLookup(attribute, value); staged.Len() > 0 {
		nodes = joinNodeSlices(nodes, staged)
		found = true
	}
	return nodes, found
}

func (tx *Tx) FindTwo(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue) (*Node, bool) {
	nodes, found := tx.FindTwoMulti(attribute, value, attribute2, value2)
	if !found {
		return nil, false
	}
	return nodes.First(), nodes.Len() == 1
}

func (tx *Tx) FindTwoMulti(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue) (NodeSlice, bool) {
	tx.checkRead()
	var nodes NodeSlice
	var found bool
	if !tx.load {
		nodes, _ = tx.g.FindTwoMulti(attribute, value, attribute2, value2)
		nodes = tx.scoped(nodes)
		found = nodes.Len() > 0
	}
	staged := tx.stagedLookup(attribute, value)
	if staged.Len() > 0 {
		var both NodeSlice
		staged.Iterate(func(o *Node) bool {
			if o.HasAttrValue(attribute2, value2) {
				both.Add(o)
			}
			return true
		})
		if both.Len() > 0 {
			nodes = joinNodeSlices(nodes, both)
			found = true
		}
	}
	return nodes, found
}

func joinNodeSlices(a, b NodeSlice) NodeSlice {
	result := NewNodeSlice(a.Len() + b.Len())
	result.nodes = append(append(result.nodes, a.nodes...), b.nodes...)
	return result
}

func (tx *Tx) FindAdjacentSID(s windowssecurity.SID, relativeTo *Node) (*Node, bool) {
	tx.checkRead()
	if !tx.load {
		if found, ok := tx.baseAdjacentSID(s, relativeTo); ok {
			return found, true
		}
	}
	if p, found := tx.byKey[sidKey(s, relativeTo)]; found {
		return p.view, true
	}
	return tx.findStagedAdjacentSID(s, relativeTo)
}

// findStagedAdjacentSID finds a staged node for a SID as seen from
// relativeTo, with the scopes of IndexedGraph.FindAdjacentSID.
func (tx *Tx) findStagedAdjacentSID(s windowssecurity.SID, relativeTo *Node) (*Node, bool) {
	return adjacentSIDAmong(tx.stagedLookup(ObjectSid, NVSID(s)), s, relativeTo)
}

// findScopedAdjacentSID finds a node of the transaction's loader for a SID
// as seen from relativeTo, ignoring other loaders' nodes for the same SID.
func (tx *Tx) findScopedAdjacentSID(s windowssecurity.SID, relativeTo *Node) (*Node, bool) {
	// Well-known SIDs exist once per machine; the loader's candidates come
	// straight from the index instead of filtering every loader's.
	nodes, _ := tx.g.FindTwoMulti(ObjectSid, NVSID(s), DataLoader, tx.loaderNV)
	return adjacentSIDAmong(nodes, s, relativeTo)
}

// baseAdjacentSID looks a SID up in the graph, as the transaction may see it.
func (tx *Tx) baseAdjacentSID(s windowssecurity.SID, relativeTo *Node) (*Node, bool) {
	if tx.loader != "" {
		return tx.findScopedAdjacentSID(s, relativeTo)
	}
	return tx.g.findAdjacentSID(s, relativeTo)
}

// adjacentSIDAmong picks the node for a SID as seen from relativeTo among
// candidates with that SID, with the scopes of IndexedGraph.FindAdjacentSID.
func adjacentSIDAmong(candidates NodeSlice, s windowssecurity.SID, relativeTo *Node) (*Node, bool) {
	if candidates.Len() == 0 {
		return nil, false
	}
	first := func(scope Attribute, value AttributeValue) (*Node, bool) {
		var result *Node
		candidates.Iterate(func(n *Node) bool {
			if scope == NonExistingAttribute || CompareAttributeValues(n.OneAttr(scope), value) {
				result = n
				return false
			}
			return true
		})
		return result, result != nil
	}
	if relativeTo == nil {
		return first(NonExistingAttribute, AttributeValue{})
	}
	domainContext := relativeTo.OneAttr(DomainContext)
	dataSource := relativeTo.OneAttr(DataSource)
	switch {
	case relativeTo.Type() == NodeTypeMachine && !dataSource.IsNil() && s.StripRID() == relativeTo.SID():
		return first(DataSource, dataSource)
	case s.Component(2) == 21 && s.Component(3) != 0:
		if candidates.Len() != 1 {
			return nil, false
		}
		return candidates.First(), true
	}
	if !domainContext.IsNil() {
		if o, found := first(DomainContext, domainContext); found {
			return o, true
		}
	}
	if !dataSource.IsNil() {
		if o, found := first(DataSource, dataSource); found {
			return o, true
		}
	}
	if !domainContext.IsNil() || !dataSource.IsNil() {
		return nil, false
	}
	return first(NonExistingAttribute, AttributeValue{})
}

func (tx *Tx) DistinguishedParent(o *Node) (*Node, bool) {
	tx.checkRead()
	if !tx.load {
		if parent, found := tx.g.DistinguishedParent(o); found && tx.inScope(parent) {
			return parent, true
		}
	}
	if parentDN := parentDistinguishedName(o.DN()); parentDN != "" {
		return tx.Find(DistinguishedName, NV(parentDN))
	}
	return nil, false
}

func (tx *Tx) GetEdge(from, to *Node) (EdgeBitmap, bool) {
	tx.checkRead()
	eb, found := tx.g.GetEdge(from, to)
	if pe := tx.edges[[2]endpoint{from.endpointIn(tx), to.endpointIn(tx)}]; pe != nil {
		if pe.replace {
			eb = pe.set
		} else {
			eb = eb.Merge(pe.set)
		}
		eb = eb.Intersect(pe.clear.Invert())
		found = !eb.IsBlank()
	}
	return eb, found
}

// IterateEdges visits the edges of a node in the graph as it was when the
// transaction began.
func (tx *Tx) IterateEdges(o *Node, direction EdgeDirection, iter func(target *Node, ebm EdgeBitmap) bool) {
	tx.checkRead()
	tx.g.IterateEdges(o, direction, iter)
}

func (tx *Tx) Edges(o *Node, direction EdgeDirection) EdgeFilter {
	tx.checkRead()
	return tx.g.Edges(o, direction)
}

func (tx *Tx) EdgeIteratorRecursive(node *Node, direction EdgeDirection, edgeMatch EdgeBitmap, excludemyself bool, goDeeperFunc func(source, target *Node, edge EdgeBitmap, depth int) bool) {
	tx.checkRead()
	tx.g.EdgeIteratorRecursive(node, direction, edgeMatch, excludemyself, goDeeperFunc)
}

// --- Edge writes ------------------------------------------------------------------

func (tx *Tx) pendingEdgeFor(from, to NodeRef) *pendingEdge {
	tx.checkWrite()
	key := [2]endpoint{from.endpointIn(tx), to.endpointIn(tx)}
	pe := tx.edges[key]
	if pe == nil {
		pe = &pendingEdge{from: key[0], to: key[1]}
		tx.edges[key] = pe
		tx.edgeSeq = append(tx.edgeSeq, pe)
	}
	return pe
}

// EdgeTo adds an edge. Like IndexedGraph.EdgeTo, an edge from a node to
// itself, from SELF, or between nodes for the same SID is not added.
func (tx *Tx) EdgeTo(from, to NodeRef, edge Edge) {
	pe := tx.pendingEdgeFor(from, to)
	pe.set = pe.set.Set(edge)
	pe.clear = pe.clear.Clear(edge)
}

// EdgeBecause adds an edge and records why it exists. An edge can have
// several causes; each is kept.
func (tx *Tx) EdgeBecause(from, to NodeRef, edge Edge, source Source) {
	tx.EdgeBecauseEx(from, to, edge, false, source)
}

// EdgeBecauseEx is EdgeBecause that, when forced, keeps edges between nodes
// for the same SID, such as a domain's Authenticated Users and a machine's.
func (tx *Tx) EdgeBecauseEx(from, to NodeRef, edge Edge, force bool, source Source) {
	pe := tx.pendingEdgeFor(from, to)
	pe.force = pe.force || force
	pe.set = pe.set.Set(edge)
	pe.clear = pe.clear.Clear(edge)
	var about endpoint
	if source.About != nil {
		about = source.About.endpointIn(tx)
	}
	pe.sources = append(pe.sources, pendingSource{edge, source.Kind, about, source.Detail})
}

// EdgeToEx is EdgeTo that, when forced, keeps edges between nodes for the
// same SID.
func (tx *Tx) EdgeToEx(from, to NodeRef, edge Edge, force bool) {
	pe := tx.pendingEdgeFor(from, to)
	pe.set = pe.set.Set(edge)
	pe.clear = pe.clear.Clear(edge)
	pe.force = pe.force || force
}

func (tx *Tx) EdgeClear(from, to NodeRef, edge Edge) {
	pe := tx.pendingEdgeFor(from, to)
	pe.set = pe.set.Clear(edge)
	pe.clear = pe.clear.Set(edge)
}

// SetEdgeBecause merges a whole edge bitmap into the existing one, like
// SetEdge, and records the same cause for each edge type in it.
func (tx *Tx) SetEdgeBecause(from, to NodeRef, eb EdgeBitmap, source Source) {
	tx.SetEdge(from, to, eb, true)
	pe := tx.pendingEdgeFor(from, to)
	var about endpoint
	if source.About != nil {
		about = source.About.endpointIn(tx)
	}
	for _, edge := range eb.Edges() {
		pe.sources = append(pe.sources, pendingSource{edge, source.Kind, about, source.Detail})
	}
}

// SetEdge sets a whole edge bitmap, merged into the existing one or
// replacing it.
func (tx *Tx) SetEdge(from, to NodeRef, eb EdgeBitmap, merge bool) {
	pe := tx.pendingEdgeFor(from, to)
	if merge {
		pe.set = pe.set.Merge(eb)
		pe.clear = pe.clear.Intersect(eb.Invert())
	} else {
		pe.set, pe.clear, pe.replace = eb, EdgeBitmap{}, true
	}
	pe.unfiltered = true
}

// --- Parallel writes --------------------------------------------------------------

// Fork returns transactions for count goroutines that write in parallel.
// Join merges their writes back in order, so the result is the same as if
// one goroutine had made them in sequence.
func (tx *Tx) Fork(count int) []*Tx {
	forks := make([]*Tx, count)
	for i := range forks {
		forks[i] = tx.g.Begin(tx.name)
		forks[i].noReads, forks[i].readOnly = tx.noReads, tx.readOnly
		forks[i].origin = tx.root()
		forks[i].load, forks[i].loadRoot = tx.load, tx.loadRoot
		if tx.loader != "" {
			forks[i].scopeTo(tx.loader)
		}
	}
	return forks
}

// root is the transaction a fork came from, or the transaction itself.
func (tx *Tx) root() *Tx {
	if tx.origin != nil {
		return tx.origin
	}
	return tx
}

// Join appends the writes of forked transactions to tx, in order. Forks can
// also be committed directly, g.Commit(forks...), which is cheaper.
func (tx *Tx) Join(forks []*Tx) {
	for _, f := range forks {
		tx.absorb(f)
	}
}

// absorb moves another transaction's writes into this one, keeping their
// order. Staged nodes with the same identity become one.
func (tx *Tx) absorb(other *Tx) {
	remap := map[*pendingNode]*pendingNode{}
	mapEndpoint := func(ep endpoint) endpoint {
		if ep.p != nil {
			if mapped, found := remap[ep.p]; found {
				return endpoint{p: mapped}
			}
		}
		return ep
	}
	for _, p := range other.pending {
		var target *pendingNode
		switch p.kind {
		case pendingBase:
			h := tx.Node(p.base)
			target = h.pending()
		case pendingKeyed, pendingSID:
			if existing, found := tx.byKey[p.key]; found {
				target = existing
			}
		}
		if target == nil {
			// New to this transaction: take it over as it is.
			tx.pending = append(tx.pending, p)
			if p.view != nil {
				tx.views[p.view] = p
				for a := range tx.staged {
					tx.indexStagedValues(p, a, p.view.Attr(a))
				}
			}
			if p.kind == pendingKeyed || p.kind == pendingSID {
				tx.byKey[p.key] = p
			}
			remap[p] = p
			continue
		}
		remap[p] = target
		for _, op := range p.ops {
			op.parent = mapEndpoint(op.parent)
			TxNode{tx: tx, p: target}.record(op)
		}
	}
	for _, p := range other.pending {
		if p.kind == pendingSID {
			remap[p].relativeTo = mapEndpoint(p.relativeTo)
		}
		for i := range remap[p].ops {
			remap[p].ops[i].parent = mapEndpoint(remap[p].ops[i].parent)
		}
	}
	for _, pe := range other.edgeSeq {
		key := [2]endpoint{mapEndpoint(pe.from), mapEndpoint(pe.to)}
		existing := tx.edges[key]
		if existing == nil {
			moved := *pe
			moved.from, moved.to = key[0], key[1]
			moved.sources = make([]pendingSource, len(pe.sources))
			for i, source := range pe.sources {
				source.about = mapEndpoint(source.about)
				moved.sources[i] = source
			}
			tx.edges[key] = &moved
			tx.edgeSeq = append(tx.edgeSeq, &moved)
			continue
		}
		if pe.replace {
			existing.set, existing.clear, existing.replace = pe.set, EdgeBitmap{}, true
		} else {
			existing.set = existing.set.Intersect(pe.clear.Invert()).Merge(pe.set)
			existing.clear = existing.clear.Intersect(pe.set.Invert()).Merge(pe.clear)
		}
		existing.force = existing.force || pe.force
		existing.unfiltered = existing.unfiltered || pe.unfiltered
		for _, source := range pe.sources {
			source.about = mapEndpoint(source.about)
			existing.sources = append(existing.sources, source)
		}
	}
}

// --- Node helpers -------------------------------------------------------------------

// shadowCopy is a private copy of a node's attributes, for a transaction
// that reads a node after writing to it.
func (o *Node) shadowCopy() *Node {
	o.rlock()
	shadow := &Node{id: o.id, sdcache: o.sdcache, parent: o.parent, children: o.children, objecttype: o.objecttype}
	o.runlock()
	o.values.Iterate(func(a Attribute, values AttributeValues) bool {
		shadow.values.set(a, slices.Clone(values))
		return true
	})
	return shadow
}

// applyNodeOp applies a write to a node. resolve maps a parent endpoint to
// a node; when it is nil, parent links are not applied.
func applyNodeOp(o *Node, op nodeOp, resolve func(endpoint) *Node) {
	switch op.kind {
	case nodeOpSet:
		o.set(op.attr, op.values...)
	case nodeOpAdd:
		o.add(op.attr, op.values...)
	case nodeOpSetMany:
		o.setMany(op.attrs, op.values)
	case nodeOpClear:
		o.clear(op.attr)
	case nodeOpTag:
		if !o.HasTag(op.tag) {
			o.add(Tag, NV(op.tag))
		}
	case nodeOpChildOf:
		if resolve != nil {
			if parent := resolve(op.parent); parent != nil {
				o.childOf(parent)
			}
		}
	}
}

func parentDistinguishedName(dn string) string {
	if dn == "" {
		return ""
	}
	return util.ParentDistinguishedName(dn)
}
