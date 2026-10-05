package engine

import (
	"fmt"
	"maps"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// Commit applies the transaction's writes to the graph.
func (tx *Tx) Commit() error {
	if tx.collection && !tx.writesToGraph() {
		return tx.g.commitCollection(tx)
	}
	return tx.g.Commit(tx)
}

// writesToGraph reports whether the transaction writes to nodes already in
// the graph.
func (tx *Tx) writesToGraph() bool {
	return slices.ContainsFunc(tx.pending, func(p *pendingNode) bool { return p.kind == pendingBase })
}

// commitCollection commits a collection that only adds nodes. Its
// identities resolve among its own nodes only, so they are resolved, and
// its writes applied, in a graph of the collection's own without the commit
// lock; only adding the nodes, parent claims and edges take it. Loading
// thousands of machine collections is otherwise serialized on the lock.
func (g *IndexedGraph) commitCollection(tx *Tx) error {
	private := &IndexedGraph{
		DefaultValues: g.DefaultValues,
		multiindexes:  map[AttributePair]*MultiIndex{},
		edgeCombos:    g.edgeCombos,
	}
	staged := committer{g: private, loadOnly: true, changedAttrs: map[Attribute]struct{}{}}
	tx.g = private
	staged.resolveNodes(tx)
	tx.g = g

	// The collection's nodes are appended to the graph in order, so edges
	// between two of them are folded here, by their positions in the
	// collection, into the edge each pair ends up with.
	var own []indexedEdgeMutation
	var outside []nodeEdgeMutation
	for _, m := range staged.appendEdgeWrites(tx, nil) {
		from, fromOwn := private.nodeLookup.Load(m.From)
		to, toOwn := private.nodeLookup.Load(m.To)
		if fromOwn && toOwn {
			own = append(own, indexedEdgeMutation{From: from, To: to, EdgeBitmap: m.EdgeBitmap, Edge: m.Edge, Merge: m.Merge, Clear: m.Clear})
		} else {
			outside = append(outside, m)
		}
	}
	sortEdgeMutations(own)
	type ownEdge struct {
		from, to NodeIndex
		combo    EdgeCombo
	}
	var edges []ownEdge
	foldEdgeMutations(own,
		func(from, to NodeIndex) EdgeBitmap { return EdgeBitmap{} },
		func(from, to NodeIndex, edge EdgeBitmap) {
			if !edge.IsBlank() {
				edges = append(edges, ownEdge{from, to, g.edgeBitmapToEdgeCombo(edge)})
			}
		})

	base, err := g.addCollectionNodes(tx, private.nodes, staged.conflicts)

	// Only this commit knows the new nodes, so their edges are built without
	// any lock and installed per node.
	var built [2]map[NodeIndex]map[NodeIndex]EdgeCombo // by direction
	for direction := range built {
		built[direction] = map[NodeIndex]map[NodeIndex]EdgeCombo{}
	}
	add := func(direction EdgeDirection, node, other NodeIndex, combo EdgeCombo) {
		targets := built[direction][node]
		if targets == nil {
			targets = map[NodeIndex]EdgeCombo{}
			built[direction][node] = targets
		}
		targets[other] = combo
	}
	for _, e := range edges {
		add(Out, e.from+base, e.to+base, e.combo)
		add(In, e.to+base, e.from+base, e.combo)
	}
	if len(edges) > 0 {
		g.edgeMutex.Lock()
		for direction := range built {
			for node, targets := range built[direction] {
				if existing := g.edges[direction].get(node); existing != nil {
					maps.Copy(existing, targets)
				} else {
					g.edges[direction].set(node, targets)
				}
			}
		}
		g.edgeVersion++
		g.edgeMutex.Unlock()
	}
	// Edges to nodes that were already in the graph go the usual way.
	g.applyIndexedEdgeMutations(g.resolveEdgeMutations(outside))
	g.applyProvenance(staged.appendProvenance(tx, nil))
	return err
}

// addCollectionNodes adds a collection's nodes and parent claims under the
// commit lock and returns where the first node landed.
func (g *IndexedGraph) addCollectionNodes(tx *Tx, nodes []*Node, conflicts []string) (NodeIndex, error) {
	requested := time.Now()
	g.commitMutex.Lock()
	locked := time.Now()
	defer func() {
		g.commitStats.commits.Add(1)
		g.commitStats.waiting.Add(int64(locked.Sub(requested)))
		g.commitStats.holding.Add(int64(time.Since(locked)))
		g.commitMutex.Unlock()
	}()
	g.joinLoadRoot(tx)
	base := g.addCollection(nodes)
	c := committer{g: g, loadOnly: true, changedAttrs: map[Attribute]struct{}{}}
	c.applyParents(tx)
	if conflicts := append(conflicts, c.conflicts...); len(conflicts) > 0 {
		return base, fmt.Errorf("invalid writes:\n%s", strings.Join(conflicts, "\n"))
	}
	return base, nil
}

// joinLoadRoot adds a loader's root with its first commit.
func (g *IndexedGraph) joinLoadRoot(tx *Tx) {
	if tx.loadRoot != nil && !g.Contains(tx.loadRoot) {
		g.add(tx.loadRoot)
		g.loadRoots = append(g.loadRoots, tx.loadRoot)
		if g.Root() != nil {
			tx.loadRoot.childOf(g.Root())
		}
	}
}

// Commit applies transactions to the graph in the order given. Nodes that
// transactions staged are resolved by identity, so two transactions that
// stage the same node end up with one. Two transactions setting the same
// single-valued attribute of a node to different values is a conflict: it
// means a missing dependency between them, and the commit reports it.
func (g *IndexedGraph) Commit(txs ...*Tx) error {
	requested := time.Now()
	g.commitMutex.Lock()
	locked := time.Now()
	defer func() {
		g.commitStats.commits.Add(1)
		g.commitStats.waiting.Add(int64(locked.Sub(requested)))
		g.commitStats.holding.Add(int64(time.Since(locked)))
		g.commitMutex.Unlock()
	}()
	c := committer{g: g, loadOnly: !slices.ContainsFunc(txs, func(tx *Tx) bool { return !tx.load }), changedAttrs: map[Attribute]struct{}{}, lookupAttrs: map[Attribute]struct{}{
		DistinguishedName: {}, ObjectSid: {}, DomainContext: {}, DataSource: {},
	}}
	steps := commitSteps{start: locked}
	defer steps.report(txs)
	for _, tx := range txs {
		g.joinLoadRoot(tx)
	}
	if !sameTransaction(txs) {
		// Writes can only conflict between transactions; forks of one
		// transaction are one.
		c.setBy = map[setKey]setRecord{}
	}
	for _, tx := range txs {
		for _, p := range tx.pending {
			if p.kind == pendingKeyed {
				c.lookupAttrs[p.key.attr1] = struct{}{}
				if p.key.attr2 != NonExistingAttribute {
					c.lookupAttrs[p.key.attr2] = struct{}{}
				}
			}
		}
	}
	// Nodes are resolved in the order they were staged, each getting its
	// attribute writes right away: a node staged later, such as a SID
	// relative to a machine, is resolved against the attributes earlier
	// writes gave that machine. Parent links follow once all nodes exist.
	if c.setBy == nil && !hasIdentityWork(txs) && !slices.ContainsFunc(txs, func(tx *Tx) bool { return tx.load }) {
		// Nothing is resolved by identity, so attribute writes to nodes in
		// the graph cannot change how other nodes resolve: apply them in
		// parallel, each node's writes in order.
		c.resolveAndWriteParallel(txs)
	} else {
		for _, tx := range txs {
			c.resolveNodes(tx)
		}
	}
	steps.mark("nodes")
	for _, tx := range txs {
		c.applyParents(tx)
	}
	steps.mark("parents")
	var mutations []nodeEdgeMutation
	for _, tx := range txs {
		mutations = c.appendEdgeWrites(tx, mutations)
	}
	g.applyIndexedEdgeMutations(g.resolveEdgeMutations(mutations))
	var causes []provenanceWrite
	for _, tx := range txs {
		causes = c.appendProvenance(tx, causes)
	}
	g.applyProvenance(causes)
	steps.mark("edges")
	g.dropIndexesFor(c.changedAttrs)
	steps.mark("indexes")
	if len(c.conflicts) > 0 {
		return fmt.Errorf("invalid writes:\n%s", strings.Join(c.conflicts, "\n"))
	}
	return nil
}

type setKey struct {
	node *Node
	attr Attribute
}

type setRecord struct {
	tx     string
	values AttributeValues
}

type committer struct {
	g            *IndexedGraph
	lookupAttrs  map[Attribute]struct{} // attributes this commit finds nodes by
	changedAttrs map[Attribute]struct{} // attributes whose indexes may be stale, dropped at the end
	// loadOnly: every transaction is a load. Its writes mostly add values,
	// so indexes are kept up to date instead of dropped, which would make
	// every following loader commit rebuild them over the whole graph.
	loadOnly  bool
	setBy     map[setKey]setRecord
	conflicts []string
}

func (c *committer) resolve(ep endpoint) *Node {
	if ep.p == nil {
		return ep.node
	}
	return ep.p.resolved
}

func (c *committer) resolveNodes(tx *Tx) {
	g := c.g
	for _, p := range tx.pending {
		c.resolveNode(g, tx, p)
		c.applyAttributeWrites(tx, p)
	}
}

func (c *committer) resolveNode(g *IndexedGraph, tx *Tx, p *pendingNode) {
	switch p.kind {
	case pendingBase:
		p.resolved, p.existed = p.base, true
		if !g.Contains(p.base) {
			c.conflicts = append(c.conflicts, fmt.Sprintf("a write to %v, which is not in the graph", p.base.Label()))
		}
	case pendingNew:
		g.add(p.view)
		p.resolved = p.view
		tx.remember(p.view)
	case pendingKeyed:
		if tx.loader != "" {
			c.resolveLoaded(g, tx, p, p.key.attr1, p.key.value1, p.key.attr2, p.key.value2)
			return
		}
		init := p.init
		nodes, found := g.findTwoMultiOrAdd(p.key.attr1, p.key.value1, p.key.attr2, p.key.value2, func() *Node {
			if p.adopt != nil {
				return p.adopt
			}
			return NewNode(init...)
		})
		p.resolved, p.existed = nodes.First(), found
		if found && tx.load {
			// What the loader states about the node is merged in, whoever
			// created it.
			for _, v := range expandFlexInit(init...) {
				c.union(p.resolved, v.attr, v.values)
			}
		}
	case pendingSID:
		if tx.loader != "" {
			// The scope was decided when the SID was staged, from what this
			// loader knew, so it does not depend on other loaders' nodes.
			attr2, value2 := p.key.scopeAttr, p.key.scope
			if value2.IsNil() {
				attr2 = NonExistingAttribute
			}
			c.resolveLoaded(g, tx, p, ObjectSid, NVSID(p.key.sid), attr2, value2)
			return
		}
		p.resolved, p.existed = g.findOrAddAdjacentSIDFound(p.key.sid, c.resolve(p.relativeTo), p.init...)
	}
}

// resolveLoaded resolves a keyed or SID node of a transaction scoped to a
// loader (a load, or a loader-phase processor) among that loader's nodes: what other loaders committed is joined by
// reference resolution once loading is done, so the result does not depend
// on the order loaders commit in.
func (c *committer) resolveLoaded(g *IndexedGraph, tx *Tx, p *pendingNode, attr1 Attribute, value1 AttributeValue, attr2 Attribute, value2 AttributeValue) {
	var candidates NodeSlice
	if attr2 == NonExistingAttribute {
		candidates, _ = g.FindMulti(attr1, value1)
	} else {
		candidates, _ = g.FindTwoMulti(attr1, value1, attr2, value2)
	}
	loader := NV(tx.loader)
	var found *Node
	candidates.Iterate(func(n *Node) bool {
		// A collection's identities only meet nodes of the same collection.
		_, own := tx.created[n]
		if (tx.collection && own) || (!tx.collection && n.HasAttrValue(DataLoader, loader)) {
			found = n
			return false
		}
		return true
	})
	if found != nil {
		p.resolved, p.existed = found, true
		if tx.load {
			for _, v := range expandFlexInit(p.init...) {
				c.union(found, v.attr, v.values)
			}
		}
		return
	}
	node := p.adopt
	if node == nil {
		if p.kind == pendingSID {
			node = NewNode(IgnoreBlanks, ObjectSid, NVSID(p.key.sid), p.key.scopeAttr, p.key.scope)
			if p.key.scopeAttr == DomainContext {
				// Like IndexedGraph.FindOrAddAdjacentSIDFound: a SID scoped to a
				// domain also carries the referring node's data source.
				if rel := c.resolve(p.relativeTo); rel != nil {
					node.setFlex(IgnoreBlanks, DataSource, rel.OneAttr(DataSource))
				}
			}
			if p.key.scope.IsNil() {
				// As in IndexedGraph.FindOrAddAdjacentSIDFound, only a global
				// SID gets the caller's values; scoped ones would share them
				// (such as a DN) across scopes.
				node.setFlex(p.init...)
			}
			node.setFlex(tx.loadValues...)
		} else {
			node = NewNode(p.init...)
		}
	}
	// The staged writes are replayed on the new node like on any other.
	g.add(node)
	p.resolved = node
	tx.remember(node)
}

// remember records a node a collection's commit added.
func (tx *Tx) remember(n *Node) {
	if !tx.collection {
		return
	}
	if tx.created == nil {
		tx.created = map[*Node]struct{}{}
	}
	tx.created[n] = struct{}{}
}

// union merges values into an attribute of a node, as a load transaction's
// writes to a node that already exists are applied. It only adds values, so
// the node's index entries are added to rather than dropped.
func (c *committer) union(node *Node, attr Attribute, values AttributeValues) {
	if node.union(attr, values) {
		c.g.reindexAttributes(node, []Attribute{attr})
	}
}

// applyIndexed applies a write in a load-only commit and keeps indexes up to
// date: values the write replaces are taken off the indexes first, and the
// node's values afterwards are added.
func (c *committer) applyIndexed(node *Node, op nodeOp) {
	var one [1]Attribute
	attrs := op.touched(&one)
	if op.kind == nodeOpSet || op.kind == nodeOpSetMany || op.kind == nodeOpClear {
		c.g.unindexAttributes(node, attrs)
	}
	applyNodeOp(node, op, nil)
	c.g.reindexAttributes(node, attrs)
}

// applyAttributeWrites replays a pending node's attribute writes on the node
// it resolved to. A new node already carries them.
func (c *committer) applyAttributeWrites(tx *Tx, p *pendingNode) {
	if p.kind == pendingNew {
		return
	}
	node := p.resolved
	if tx.load && p.existed {
		c.applyLoadWrites(p)
		return
	}
	var changed []Attribute
	var one [1]Attribute
	for _, op := range p.ops {
		switch op.kind {
		case nodeOpSet:
			c.checkConflict(tx, node, op.attr, op.values)
		case nodeOpSetMany:
			for i, a := range op.attrs {
				c.checkConflict(tx, node, a, op.values[i:i+1])
			}
		case nodeOpChildOf:
			continue
		}
		if c.loadOnly || !p.existed {
			// A node this commit created has few writes; its index entries
			// are updated in place rather than the indexes dropped.
			c.applyIndexed(node, op)
			continue
		}
		applyNodeOp(node, op, nil)
		for _, attr := range op.touched(&one) {
			c.changedAttrs[attr] = struct{}{}
			if _, lookup := c.lookupAttrs[attr]; lookup {
				changed = append(changed, attr)
			}
		}
	}
	if len(changed) > 0 {
		// Later nodes in this commit may look this node up by what was
		// just written; other indexes are dropped at the end.
		c.g.reindexAttributes(node, changed)
	}
}

// applyLoadWrites applies a load transaction's writes to a node that
// already existed: values are merged in as unions, so the result does not
// depend on which loader committed first.
func (c *committer) applyLoadWrites(p *pendingNode) {
	for _, op := range p.ops {
		switch op.kind {
		case nodeOpSet, nodeOpAdd:
			c.union(p.resolved, op.attr, op.values)
		case nodeOpSetMany:
			for i, a := range op.attrs {
				c.union(p.resolved, a, op.values[i:i+1])
			}
		case nodeOpTag:
			c.union(p.resolved, Tag, AttributeValues{NV(op.tag)})
		case nodeOpClear:
			c.applyIndexed(p.resolved, op)
		}
	}
}

func (c *committer) applyParents(tx *Tx) {
	for _, p := range tx.pending {
		if tx.load {
			// Loaders claim parents; the claims are applied once every
			// loader is done and the directory has placed its own objects,
			// so the tree does not depend on which loader came first.
			for _, op := range p.ops {
				if op.kind == nodeOpChildOf {
					if parent := c.resolve(op.parent); parent != nil {
						c.g.claimParent(p.resolved, parent)
					}
				}
			}
			continue
		}
		for _, op := range p.ops {
			if op.kind == nodeOpChildOf {
				applyNodeOp(p.resolved, op, c.resolve)
			}
		}
	}
}

func (c *committer) checkConflict(tx *Tx, node *Node, attr Attribute, values AttributeValues) {
	if c.setBy == nil || !attr.HasFlag(Single) {
		return
	}
	key := setKey{node, attr}
	previous, found := c.setBy[key]
	if found && previous.tx != tx.name && !sameValues(previous.values, values) {
		c.conflicts = append(c.conflicts, fmt.Sprintf("%q and %q both set %v on %v; they need a dependency between them", previous.tx, tx.name, attr.String(), node.Label()))
	}
	c.setBy[key] = setRecord{tx: tx.name, values: values}
}

// touched lists the attributes an op writes, using buf for a single one so
// the common case does not allocate.
func (op nodeOp) touched(buf *[1]Attribute) []Attribute {
	switch op.kind {
	case nodeOpSetMany:
		return op.attrs
	case nodeOpTag:
		buf[0] = Tag
	case nodeOpChildOf:
		return nil
	default:
		buf[0] = op.attr
	}
	return buf[:]
}

func sameValues(a, b AttributeValues) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !CompareAttributeValues(a[i], b[i]) {
			return false
		}
	}
	return true
}

// appendProvenance resolves the causes staged with the transaction's edges.
func (c *committer) appendProvenance(tx *Tx, writes []provenanceWrite) []provenanceWrite {
	for _, pe := range tx.edgeSeq {
		if len(pe.sources) == 0 {
			continue
		}
		from, to := c.resolve(pe.from), c.resolve(pe.to)
		if from == nil || to == nil {
			continue
		}
		for _, source := range pe.sources {
			writes = append(writes, provenanceWrite{from, to, source.edge, EdgeSource{source.kind, c.resolve(source.about), source.detail}})
		}
	}
	return writes
}

func (c *committer) appendEdgeWrites(tx *Tx, mutations []nodeEdgeMutation) []nodeEdgeMutation {
	for _, pe := range tx.edgeSeq {
		from, to := c.resolve(pe.from), c.resolve(pe.to)
		if from == nil || to == nil {
			continue
		}
		if !pe.unfiltered {
			if from == to {
				continue
			}
			if !pe.force {
				fromSID := from.SID()
				if fromSID == windowssecurity.SelfSID || (!fromSID.IsBlank() && fromSID == to.SID()) {
					continue
				}
			}
		}
		switch {
		case pe.replace:
			mutations = append(mutations, nodeEdgeMutation{From: from, To: to, Edge: NonExistingEdge, EdgeBitmap: pe.set})
		default:
			if !pe.set.IsBlank() {
				mutations = append(mutations, nodeEdgeMutation{From: from, To: to, Edge: NonExistingEdge, EdgeBitmap: pe.set, Merge: true})
			}
			if !pe.clear.IsBlank() {
				mutations = append(mutations, nodeEdgeMutation{From: from, To: to, Edge: NonExistingEdge, EdgeBitmap: pe.clear, Clear: true})
			}
		}
	}
	return mutations
}

// dropIndexesFor drops the indexes over attributes that changed; they are
// rebuilt when next used.
func (g *IndexedGraph) dropIndexesFor(attrs map[Attribute]struct{}) {
	if len(attrs) == 0 {
		return
	}
	g.indexlock.Lock()
	defer g.indexlock.Unlock()
	for a := range attrs {
		if int(a) < len(g.indexes) {
			g.indexes[a] = nil
		}
		if a == Type {
			// AttrRendered indexes ObjectCategory through Type.
			if int(ObjectCategory) < len(g.indexes) {
				g.indexes[ObjectCategory] = nil
			}
		}
	}
	for pair := range g.multiindexes {
		_, first := attrs[pair.attribute1]
		_, second := attrs[pair.attribute2]
		if first || second {
			delete(g.multiindexes, pair)
		}
	}
}

// indexedAttributes adds the attributes whose rendered values depend on the
// given ones.
func indexedAttributes(attrs []Attribute) []Attribute {
	if slices.Contains(attrs, Type) && !slices.Contains(attrs, ObjectCategory) {
		// AttrRendered indexes ObjectCategory through Type.
		return append(slices.Clip(attrs), ObjectCategory)
	}
	return attrs
}

// reindexAttributes adds a node to the existing indexes over the given
// attributes. Values it no longer has stay until the indexes are dropped,
// unless unindexAttributes took them off first.
func (g *IndexedGraph) reindexAttributes(o *Node, attrs []Attribute) {
	g.visitIndexed(o, indexedAttributes(attrs),
		func(index *Index, value AttributeValue) { index.Add(value, o, true) },
		func(index *MultiIndex, value, value2 AttributeValue) { index.Add(value, value2, o, true) })
}

// unindexAttributes takes a node off the existing indexes for its current
// values of the given attributes, before they are replaced.
func (g *IndexedGraph) unindexAttributes(o *Node, attrs []Attribute) {
	g.visitIndexed(o, indexedAttributes(attrs),
		func(index *Index, value AttributeValue) { index.Remove(value, o) },
		func(index *MultiIndex, value, value2 AttributeValue) { index.Remove(value, value2, o) })
}

func (g *IndexedGraph) visitIndexed(o *Node, attrs []Attribute, single func(*Index, AttributeValue), multi func(*MultiIndex, AttributeValue, AttributeValue)) {
	g.indexlock.RLock()
	defer g.indexlock.RUnlock()
	for _, attr := range attrs {
		if int(attr) < len(g.indexes) {
			if index := g.indexes[attr]; index != nil {
				o.AttrRendered(attr).Iterate(func(value AttributeValue) bool {
					single(index, value)
					return true
				})
			}
		}
		for pair, index := range g.multiindexes {
			if pair.attribute1 != attr && pair.attribute2 != attr {
				continue
			}
			o.Attr(pair.attribute1).Iterate(func(value AttributeValue) bool {
				o.Attr(pair.attribute2).Iterate(func(value2 AttributeValue) bool {
					multi(index, value, value2)
					return true
				})
				return true
			})
		}
	}
}

func sameTransaction(txs []*Tx) bool {
	for _, tx := range txs {
		if tx.root() != txs[0].root() {
			return false
		}
	}
	return true
}

func hasIdentityWork(txs []*Tx) bool {
	for _, tx := range txs {
		for _, p := range tx.pending {
			if p.kind == pendingKeyed || p.kind == pendingSID {
				return true
			}
		}
	}
	return false
}

// resolveAndWriteParallel resolves nodes in staging order, then applies the
// attribute writes to nodes in the graph on several workers. A node always
// goes to the same worker, which applies its writes in staging order, so the
// result is the same as applying them one by one.
func (c *committer) resolveAndWriteParallel(txs []*Tx) {
	var pending int
	for _, tx := range txs {
		pending += len(tx.pending)
	}
	workers := min(runtime.GOMAXPROCS(0), max(1, pending/4096))
	// Each worker gets its own list, a node always the same worker's. Node
	// addresses share their low bits, so they are mixed before choosing.
	base := make([][]*pendingNode, workers)
	for _, tx := range txs {
		for _, p := range tx.pending {
			c.resolveNode(c.g, tx, p)
			if p.kind == pendingBase && len(p.ops) > 0 {
				mixed := uint64(uintptr(unsafe.Pointer(p.base))) * 0x9E3779B97F4A7C15
				w := int((mixed >> 32) % uint64(workers))
				base[w] = append(base[w], p)
			}
		}
	}
	// Attributes as flags by number: maps cost more than the writes.
	var lookup []bool
	for a := range c.lookupAttrs {
		lookup = growFlags(lookup, a)
		lookup[a] = true
	}
	changed := make([][]bool, workers)
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			var reindex []Attribute
			var one [1]Attribute
			for _, p := range base[w] {
				reindex = reindex[:0]
				for _, op := range p.ops {
					if op.kind == nodeOpChildOf {
						continue
					}
					applyNodeOp(p.base, op, nil)
					for _, attr := range op.touched(&one) {
						changed[w] = growFlags(changed[w], attr)
						changed[w][attr] = true
						if int(attr) < len(lookup) && lookup[attr] {
							reindex = append(reindex, attr)
						}
					}
				}
				if len(reindex) > 0 {
					c.g.reindexAttributes(p.base, reindex)
				}
			}
		})
	}
	wg.Wait()
	for _, flags := range changed {
		for a, set := range flags {
			if set {
				c.changedAttrs[Attribute(a)] = struct{}{}
			}
		}
	}
}

// growFlags makes room for flag a.
func growFlags(flags []bool, a Attribute) []bool {
	if int(a) >= len(flags) {
		flags = append(flags, make([]bool, int(a)+1-len(flags))...)
	}
	return flags
}

// commitSteps times a commit's steps, reported when it was slow.
type commitSteps struct {
	start, last time.Time
	steps       []string
}

func (s *commitSteps) mark(step string) {
	now := time.Now()
	if s.last.IsZero() {
		s.last = s.start
	}
	s.steps = append(s.steps, fmt.Sprintf("%v %v", step, now.Sub(s.last)))
	s.last = now
}

func (s *commitSteps) report(txs []*Tx) {
	if took := time.Since(s.start); took > time.Second {
		ui.Info().Msgf("Commit of %v transactions took %v: %v", len(txs), took, strings.Join(s.steps, ", "))
	}
}

// commitStats measures how commits share the commit lock.
type commitStats struct {
	commits          atomic.Int64
	waiting, holding atomic.Int64 // nanoseconds
}

// takeCommitStats returns and resets the counts since the last call.
func (g *IndexedGraph) takeCommitStats() (commits int64, waiting, holding time.Duration) {
	return g.commitStats.commits.Swap(0), time.Duration(g.commitStats.waiting.Swap(0)), time.Duration(g.commitStats.holding.Swap(0))
}
