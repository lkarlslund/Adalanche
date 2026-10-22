package engine

import (
	"slices"
	"sync"
)

// Edge tags mark edges between two nodes, such as an analysis marking how
// it found an edge or a user marking one as an accepted risk. A tag is on one
// edge type between the pair, or, with AnyEdgeType, on the pair whatever its
// edge types. Tags are kept like edge causes: each distinct tag name once per
// graph, each edge holding small numbers. A tag lasts as long as the edges it
// is on: tags on an edge type go when the pair loses that type, tags on the
// pair when it loses its last edge.

// EdgeTag is a tag on the edges between two nodes.
type EdgeTag struct {
	Edge Edge // the edge type it is on, or AnyEdgeType for the pair
	Tag  string
}

// EdgeTagID numbers a distinct tag name within a graph.
type EdgeTagID uint32

type edgeTagEntry struct {
	edge Edge
	tag  EdgeTagID
}

func (e edgeTagEntry) edgeType() Edge { return e.edge }

// edgeTagNames interns a graph's tag names.
type edgeTagNames struct {
	sync.Mutex
	names []string
	ids   map[string]EdgeTagID
}

func (t *edgeTagNames) intern(name string) EdgeTagID {
	t.Lock()
	defer t.Unlock()
	if id, found := t.ids[name]; found {
		return id
	}
	if t.ids == nil {
		t.ids = map[string]EdgeTagID{}
	}
	id := EdgeTagID(len(t.names))
	t.names = append(t.names, name)
	t.ids[name] = id
	return id
}

func (t *edgeTagNames) lookup(name string) (EdgeTagID, bool) {
	t.Lock()
	defer t.Unlock()
	id, found := t.ids[name]
	return id, found
}

func (t *edgeTagNames) name(id EdgeTagID) string {
	t.Lock()
	defer t.Unlock()
	return t.names[id]
}

// pendingEdgeTag is a tag staged with an edge, to add or remove.
type pendingEdgeTag struct {
	edge   Edge
	tag    string
	remove bool
}

// TagEdge tags the edge of one type from one node to another, or with
// AnyEdgeType the pair whatever its edge types, once the transaction
// commits. A tag on an edge the graph does not have is dropped.
func (tx *Tx) TagEdge(from, to NodeRef, edge Edge, tag string) {
	pe := tx.pendingEdgeFor(from, to)
	pe.tags = append(pe.tags, pendingEdgeTag{edge, tag, false})
}

// UntagEdge removes a tag that TagEdge set, on the same edge type or pair.
func (tx *Tx) UntagEdge(from, to NodeRef, edge Edge, tag string) {
	pe := tx.pendingEdgeFor(from, to)
	pe.tags = append(pe.tags, pendingEdgeTag{edge, tag, true})
}

// edgeTagWrite is a tag change to apply once the edges of a commit are in.
type edgeTagWrite struct {
	from, to *Node
	pendingEdgeTag
}

// appendEdgeTags resolves the tag changes staged with the transaction's edges.
func (c *committer) appendEdgeTags(tx *Tx, writes []edgeTagWrite) []edgeTagWrite {
	for _, pe := range tx.edgeSeq {
		if len(pe.tags) == 0 {
			continue
		}
		from, to := c.resolve(pe.from), c.resolve(pe.to)
		if from == nil || to == nil {
			continue
		}
		for _, t := range pe.tags {
			writes = append(writes, edgeTagWrite{from, to, t})
		}
	}
	return writes
}

// applyEdgeTags applies tag changes, in order, to edges that exist after the
// commit.
func (g *IndexedGraph) applyEdgeTags(writes []edgeTagWrite) {
	if len(writes) == 0 {
		return
	}
	g.edgeMutex.Lock()
	defer g.edgeMutex.Unlock()
	for _, w := range writes {
		from, ok := g.nodeLookup.Load(w.from)
		if !ok {
			continue
		}
		to, ok := g.nodeLookup.Load(w.to)
		if !ok {
			continue
		}
		entry := edgeTagEntry{w.edge, g.tagNames.intern(w.tag)}
		targets := g.edgeTags.get(from)
		if w.remove {
			if targets != nil {
				targets[to] = slices.DeleteFunc(targets[to], func(e edgeTagEntry) bool { return e == entry })
				if len(targets[to]) == 0 {
					delete(targets, to)
				}
			}
			continue
		}
		edge, found := g.loadEdge(from, to, Out)
		if !found || edge.IsBlank() || (w.edge != AnyEdgeType && !edge.IsSet(w.edge)) {
			continue
		}
		if targets == nil {
			targets = map[NodeIndex][]edgeTagEntry{}
			g.edgeTags.set(from, targets)
		}
		if !slices.Contains(targets[to], entry) {
			targets[to] = append(targets[to], entry)
		}
	}
}

// EdgeTags returns the tags on the edges from one node to another.
func (g *IndexedGraph) EdgeTags(from, to *Node) []EdgeTag {
	fromIndex, ok := g.nodeLookup.Load(from)
	if !ok {
		return nil
	}
	toIndex, ok := g.nodeLookup.Load(to)
	if !ok {
		return nil
	}
	g.edgeMutex.RLock()
	entries := slices.Clone(g.edgeTags.get(fromIndex)[toIndex])
	g.edgeMutex.RUnlock()
	result := make([]EdgeTag, len(entries))
	for i, e := range entries {
		result[i] = EdgeTag{e.edge, g.tagNames.name(e.tag)}
	}
	return result
}

// LookupEdgeTag returns the number of a tag name, if any edge was ever
// tagged with it in this graph.
func (g *IndexedGraph) LookupEdgeTag(name string) (EdgeTagID, bool) {
	return g.tagNames.lookup(name)
}

// EdgeTypesTagged returns which of the edge types in present, from one node
// to another, carry the tag: all of them when the pair carries it.
func (g *IndexedGraph) EdgeTypesTagged(from, to NodeIndex, tag EdgeTagID, present EdgeBitmap) EdgeBitmap {
	g.edgeMutex.RLock()
	defer g.edgeMutex.RUnlock()
	var tagged EdgeBitmap
	for _, e := range g.edgeTags.get(from)[to] {
		if e.tag != tag {
			continue
		}
		if e.edge == AnyEdgeType {
			return present
		}
		if present.IsSet(e.edge) {
			tagged = tagged.Set(e.edge)
		}
	}
	return tagged
}

// HasEdgeTags reports whether any edge in the graph is tagged, so searches
// can skip looking.
func (g *IndexedGraph) HasEdgeTags() bool {
	g.tagNames.Lock()
	defer g.tagNames.Unlock()
	return len(g.tagNames.names) > 0
}
