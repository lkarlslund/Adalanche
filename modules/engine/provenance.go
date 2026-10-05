package engine

import (
	"runtime"
	"slices"
	"sync"
)

// Edge provenance records why an edge exists: which GPO granted it, which
// security descriptor, which machine collection listed it. Writers state the
// cause with the edge (Tx.EdgeBecause); an edge can have several causes.
// Detail that can be worked out from the graph, such as where an inherited
// ACE was set, is left to readers.

// SourceKind is a kind of cause, registered by the integration that writes
// it.
type SourceKind uint8

var (
	sourceKindLock  sync.Mutex
	sourceKindNames = []string{"Unknown"}
)

// NewSourceKind registers a kind of edge cause.
func NewSourceKind(name string) SourceKind {
	sourceKindLock.Lock()
	defer sourceKindLock.Unlock()
	if i := slices.Index(sourceKindNames, name); i >= 0 {
		return SourceKind(i)
	}
	sourceKindNames = append(sourceKindNames, name)
	return SourceKind(len(sourceKindNames) - 1)
}

func (k SourceKind) String() string {
	sourceKindLock.Lock()
	defer sourceKindLock.Unlock()
	if int(k) < len(sourceKindNames) {
		return sourceKindNames[k]
	}
	return "Unknown"
}

// Source is a cause as a transaction states it: of a kind, about a node
// (the GPO, the machine whose collection lists it), with a short detail.
// About is left out when the cause is the edge's own target, such as the
// ACE in the target's security descriptor, so such causes repeat across
// edges and are kept once.
type Source struct {
	Kind   SourceKind
	About  NodeRef
	Detail string
}

// EdgeSource is a cause as the graph keeps it.
type EdgeSource struct {
	Kind   SourceKind
	About  *Node
	Detail string
}

// EdgeProvenance is one cause of one edge type between two nodes.
type EdgeProvenance struct {
	Edge   Edge
	Source EdgeSource
}

// SourceID numbers a distinct cause within a graph. Causes repeat across
// many edges (one GPO granting a right on every machine it applies to), so
// each is kept once.
type SourceID uint32

type edgeCause struct {
	edge   Edge
	source SourceID
}

// sourceTable interns a graph's causes.
type sourceTable struct {
	sync.Mutex
	sources []EdgeSource
	ids     map[EdgeSource]SourceID
}

func (t *sourceTable) intern(s EdgeSource) SourceID {
	t.Lock()
	defer t.Unlock()
	if id, found := t.ids[s]; found {
		return id
	}
	if t.ids == nil {
		t.ids = map[EdgeSource]SourceID{}
	}
	id := SourceID(len(t.sources))
	t.sources = append(t.sources, s)
	t.ids[s] = id
	return id
}

func (t *sourceTable) get(id SourceID) EdgeSource {
	t.Lock()
	defer t.Unlock()
	return t.sources[id]
}

// remap points causes about folded nodes at the node they were folded
// into; causes about removed nodes keep no node.
func (t *sourceTable) remap(final func(*Node) *Node) {
	t.Lock()
	defer t.Unlock()
	clear(t.ids)
	for i, s := range t.sources {
		if s.About != nil {
			s.About = final(s.About)
			t.sources[i] = s
		}
		if _, found := t.ids[s]; !found {
			t.ids[s] = SourceID(i)
		}
	}
}

// provenanceWrite is a cause to record once the edges of a commit are in.
type provenanceWrite struct {
	from, to *Node
	edge     Edge
	source   EdgeSource
}

// applyProvenance records causes for edges that exist after the commit;
// causes for edges the commit filtered out or cleared are dropped.
func (g *IndexedGraph) applyProvenance(writes []provenanceWrite) {
	if len(writes) == 0 {
		return
	}
	type resolved struct {
		from, to NodeIndex
		cause    edgeCause
	}
	// Causes repeat heavily within a commit; each distinct one is looked
	// up in the shared table once.
	ids := map[EdgeSource]SourceID{}
	list := make([]resolved, 0, len(writes))
	for _, w := range writes {
		from, ok := g.nodeLookup.Load(w.from)
		if !ok {
			continue
		}
		to, ok := g.nodeLookup.Load(w.to)
		if !ok {
			continue
		}
		id, found := ids[w.source]
		if !found {
			id = g.sources.intern(w.source)
			ids[w.source] = id
		}
		list = append(list, resolved{from, to, edgeCause{w.edge, id}})
	}

	g.edgeMutex.Lock()
	defer g.edgeMutex.Unlock()
	apply := func(r resolved) {
		edge, found := g.loadEdge(r.from, r.to, Out)
		if !found || !edge.IsSet(r.cause.edge) {
			return
		}
		targets := g.provenance.get(r.from)
		if targets == nil {
			targets = map[NodeIndex][]edgeCause{}
			g.provenance.set(r.from, targets)
		}
		if !slices.Contains(targets[r.to], r.cause) {
			targets[r.to] = append(targets[r.to], r.cause)
		}
	}
	if len(list) < parallelEdgeMutations {
		for _, r := range list {
			apply(r)
		}
		return
	}
	// Many causes: each source node's causes go to one worker, so workers
	// never share a map; the index is grown first so none resizes it.
	var highest NodeIndex
	for _, r := range list {
		highest = max(highest, r.from)
	}
	g.provenance.grow(int(highest) + 1)
	workers := runtime.GOMAXPROCS(0)
	parts := make([][]resolved, workers)
	for _, r := range list {
		w := int(r.from) % workers
		parts[w] = append(parts[w], r)
	}
	var wg sync.WaitGroup
	for _, part := range parts {
		wg.Go(func() {
			for _, r := range part {
				apply(r)
			}
		})
	}
	wg.Wait()
}

// pruneProvenance drops causes for edge types the pair no longer has.
// Callers hold edgeMutex, or own the source node's entries.
func (g *IndexedGraph) pruneProvenance(from, to NodeIndex, edge EdgeBitmap) {
	targets := g.provenance.get(from)
	if targets == nil {
		return
	}
	causes, found := targets[to]
	if !found {
		return
	}
	causes = slices.DeleteFunc(causes, func(c edgeCause) bool { return !edge.IsSet(c.edge) })
	if len(causes) == 0 {
		delete(targets, to)
	} else {
		targets[to] = causes
	}
}

// EdgeSources returns why the edges from one node to another exist, as far
// as their writers recorded it.
func (g *IndexedGraph) EdgeSources(from, to *Node) []EdgeProvenance {
	fromIndex, ok := g.nodeLookup.Load(from)
	if !ok {
		return nil
	}
	toIndex, ok := g.nodeLookup.Load(to)
	if !ok {
		return nil
	}
	g.edgeMutex.RLock()
	causes := slices.Clone(g.provenance.get(fromIndex)[toIndex])
	g.edgeMutex.RUnlock()
	result := make([]EdgeProvenance, len(causes))
	for i, c := range causes {
		result[i] = EdgeProvenance{c.edge, g.sources.get(c.source)}
	}
	return result
}

// provenanceIndex is like adjacency, with causes per target.
type provenanceIndex []map[NodeIndex][]edgeCause

func (p provenanceIndex) get(from NodeIndex) map[NodeIndex][]edgeCause {
	if int(from) < len(p) {
		return p[from]
	}
	return nil
}

func (p *provenanceIndex) set(from NodeIndex, targets map[NodeIndex][]edgeCause) {
	if int(from) >= len(*p) {
		p.grow(max(int(from)+1, 2*len(*p), 1024))
	}
	(*p)[from] = targets
}

// grow makes room for nodes up to position n-1.
func (p *provenanceIndex) grow(n int) {
	if n > len(*p) {
		grown := make(provenanceIndex, n)
		copy(grown, *p)
		*p = grown
	}
}

var (
	sourceOriginLock sync.Mutex
	sourceOrigins    = map[SourceKind]func(from, to *Node, s EdgeSource) *Node{}
)

// RegisterSourceOrigin sets how to find where causes of a kind were set,
// for kinds where that takes knowledge of the data, such as where an
// inherited ACE came from.
func RegisterSourceOrigin(kind SourceKind, origin func(from, to *Node, s EdgeSource) *Node) {
	sourceOriginLock.Lock()
	defer sourceOriginLock.Unlock()
	sourceOrigins[kind] = origin
}

// Origin returns the node where the cause of an edge from one node to
// another was set: as registered for its kind, or else the node the cause is
// about. Nil means it cannot be told.
func (s EdgeSource) Origin(from, to *Node) *Node {
	sourceOriginLock.Lock()
	origin := sourceOrigins[s.Kind]
	sourceOriginLock.Unlock()
	if origin != nil {
		return origin(from, to, s)
	}
	return s.About
}
