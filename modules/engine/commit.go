package engine

import (
	"fmt"
	"strings"

	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// Commit applies the transaction's writes to the graph.
func (tx *Tx) Commit() error {
	return tx.g.Commit(tx)
}

// Commit applies transactions to the graph in the order given. Nodes that
// transactions staged are resolved by identity, so two transactions that
// stage the same node end up with one. Two transactions setting the same
// single-valued attribute of a node to different values is a conflict: it
// means a missing dependency between them, and the commit reports it.
func (g *IndexedGraph) Commit(txs ...*Tx) error {
	g.commitMutex.Lock()
	defer g.commitMutex.Unlock()
	c := committer{g: g, changedAttrs: map[Attribute]struct{}{}, lookupAttrs: map[Attribute]struct{}{
		DistinguishedName: {}, ObjectSid: {}, DomainContext: {}, DataSource: {},
	}}
	if len(txs) > 1 {
		// Writes can only conflict between transactions.
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
	for _, tx := range txs {
		c.resolveNodes(tx)
	}
	for _, tx := range txs {
		c.applyParents(tx)
	}
	var mutations []nodeEdgeMutation
	for _, tx := range txs {
		mutations = c.appendEdgeWrites(tx, mutations)
	}
	g.applyIndexedEdgeMutations(g.resolveEdgeMutations(mutations))
	g.dropIndexesFor(c.changedAttrs)
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
	changedAttrs map[Attribute]struct{}
	setBy        map[setKey]setRecord
	conflicts    []string
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
		c.resolveNode(g, p)
		c.applyAttributeWrites(tx, p)
	}
}

func (c *committer) resolveNode(g *IndexedGraph, p *pendingNode) {
	{
		switch p.kind {
		case pendingBase:
			p.resolved = p.base
			if !g.Contains(p.base) {
				c.conflicts = append(c.conflicts, fmt.Sprintf("a write to %v, which is not in the graph", p.base.Label()))
			}
		case pendingNew:
			g.add(p.view)
			p.resolved = p.view
		case pendingKeyed:
			init := p.init
			nodes, _ := g.findTwoMultiOrAdd(p.key.attr1, p.key.value1, p.key.attr2, p.key.value2, func() *Node {
				return NewNode(init...)
			})
			p.resolved = nodes.First()
		case pendingSID:
			p.resolved, _ = g.findOrAddAdjacentSIDFound(p.key.sid, c.resolve(p.relativeTo), p.init...)
		}
	}
}

// applyAttributeWrites replays a pending node's attribute writes on the node
// it resolved to. A new node already carries them.
func (c *committer) applyAttributeWrites(tx *Tx, p *pendingNode) {
	if p.kind == pendingNew {
		return
	}
	node := p.resolved
	var changed []Attribute
	for _, op := range p.ops {
		attr := op.attr
		switch op.kind {
		case nodeOpSet:
			c.checkConflict(tx, node, op)
		case nodeOpTag:
			attr = Tag
		case nodeOpChildOf:
			continue
		}
		c.changedAttrs[attr] = struct{}{}
		applyNodeOp(node, op, nil)
		if _, lookup := c.lookupAttrs[attr]; lookup {
			changed = append(changed, attr)
		}
	}
	if len(changed) > 0 {
		// Later nodes in this commit may look this node up by what was
		// just written; other indexes are dropped at the end.
		c.g.reindexAttributes(node, changed)
	}
}

func (c *committer) applyParents(tx *Tx) {
	for _, p := range tx.pending {
		for _, op := range p.ops {
			if op.kind == nodeOpChildOf {
				applyNodeOp(p.resolved, op, c.resolve)
			}
		}
	}
}

func (c *committer) checkConflict(tx *Tx, node *Node, op nodeOp) {
	if c.setBy == nil || !op.attr.HasFlag(Single) {
		return
	}
	key := setKey{node, op.attr}
	previous, found := c.setBy[key]
	if found && previous.tx != tx.name && !sameValues(previous.values, op.values) {
		c.conflicts = append(c.conflicts, fmt.Sprintf("%q and %q both set %v on %v; they need a dependency between them", previous.tx, tx.name, op.attr.String(), node.Label()))
	}
	c.setBy[key] = setRecord{tx: tx.name, values: op.values}
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

// reindexAttributes adds a node to the existing indexes over the given
// attributes. Values it no longer has stay until the indexes are dropped.
func (g *IndexedGraph) reindexAttributes(o *Node, attrs []Attribute) {
	g.indexlock.RLock()
	defer g.indexlock.RUnlock()
	for _, attr := range attrs {
		if int(attr) < len(g.indexes) {
			if index := g.indexes[attr]; index != nil {
				o.AttrRendered(attr).Iterate(func(value AttributeValue) bool {
					index.Add(value, o, true)
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
					index.Add(value, value2, o, true)
					return true
				})
				return true
			})
		}
	}
}
