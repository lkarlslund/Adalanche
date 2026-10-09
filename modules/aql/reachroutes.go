package aql

import (
	"fmt"
	"maps"
	"runtime"
	"slices"
	"sync"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/ui"
)

// ReachRoutes says which routes a REACH query keeps.
type ReachRoutes int

const (
	RoutesAll      ReachRoutes = iota // every route within the query's rules
	RoutesShortest                    // every shortest route from each start to each end
	RoutesCheapest                    // one cheapest route from each start to each end
)

// reachPairWork bounds the work of searching from every node on the smaller
// side of a query, in nodes and edges visited. Over it, one search from the
// whole side keeps a route for each node on the other side, from the
// nearest node on this side.
const reachPairWork = 1_000_000_000

// recombinable reports whether any route over the result's edges from a
// start to an end, within the depth limit and passing only nodes the path
// node filter allows, is a valid route of the query: a single step with
// one direction and at most one edge required.
func (s *reachSearch) recombinable() bool {
	if len(s.aqlq.Next) != 1 {
		return false
	}
	step := s.aqlq.Next[0]
	return step.MinIterations <= 1 && (step.Direction == engine.In || step.Direction == engine.Out)
}

// passable reports whether a route may pass through v on its way: the path
// node filter allows it. A route's first and last nodes need not match.
func (s *reachSearch) passable(v engine.NodeIndex) bool {
	required := s.aqlq.Next[0].pathNodeRequirementCache
	return required == nil || required.Contains(s.aqlq.datasource.NodeAt(v))
}

// pairArc is an edge of the result as the search for pairs takes it.
type pairArc struct {
	to          int32
	key         int32   // position in the result's edges
	probability float64 // of the edge, 0-1
}

// pairGraph is the result of REACH, renumbered densely for searching
// between pairs of a start and an end node.
type pairGraph struct {
	s     *reachSearch
	nodes    []engine.NodeIndex
	passable []bool
	keys     []reachKey
	types []engine.EdgeBitmap
	ranks []uint32
	// search runs from start to end, against the edges when the step goes
	// in; along runs with the edges.
	search, against, along [][]pairArc
	depth                  int
}

func (s *reachSearch) newPairGraph(edges map[reachKey]reachResultEdge, nodeLength map[engine.NodeIndex]int) *pairGraph {
	ds := s.aqlq.datasource
	step := s.aqlq.Next[0]
	pg := &pairGraph{s: s, depth: min(s.maxDepth, max(step.MaxIterations, 1))}
	local := map[engine.NodeIndex]int32{}
	id := func(v engine.NodeIndex) int32 {
		if i, found := local[v]; found {
			return i
		}
		i := int32(len(pg.nodes))
		local[v] = i
		pg.nodes = append(pg.nodes, v)
		pg.passable = append(pg.passable, s.passable(v))
		pg.ranks = append(pg.ranks, s.adjacency.Ranks[v])
		return i
	}
	for _, v := range slices.Sorted(maps.Keys(nodeLength)) {
		id(v)
	}
	for key := range edges {
		pg.keys = append(pg.keys, key)
	}
	slices.SortFunc(pg.keys, func(a, b reachKey) int {
		if a.from != b.from {
			return int(a.from) - int(b.from)
		}
		return int(a.to) - int(b.to)
	})
	for _, key := range pg.keys {
		id(key.from)
		id(key.to)
	}
	pg.search = make([][]pairArc, len(pg.nodes))
	pg.against = make([][]pairArc, len(pg.nodes))
	pg.along = make([][]pairArc, len(pg.nodes))
	pg.types = make([]engine.EdgeBitmap, len(pg.keys))
	for i, key := range pg.keys {
		re := edges[key]
		pg.types[i] = re.edges
		from, to := local[key.from], local[key.to]
		p := float64(re.edges.MaxProbability(ds.NodeAt(key.from), ds.NodeAt(key.to))) / 100
		pg.along[from] = append(pg.along[from], pairArc{to, int32(i), p})
		if step.Direction == engine.In {
			from, to = to, from
		}
		pg.search[from] = append(pg.search[from], pairArc{to, int32(i), p})
		pg.against[to] = append(pg.against[to], pairArc{from, int32(i), p})
	}
	return pg
}

func (pg *pairGraph) node(i int32) *engine.Node {
	return pg.s.aqlq.datasource.NodeAt(pg.nodes[i])
}

// pairSearcher searches from one node at a time; each worker has its own.
type pairSearcher struct {
	pg        *pairGraph
	routes    *engine.RouteChecker
	epoch     uint32
	seen      []uint32
	dist      []int16
	best      []float64
	parent    []int32
	parentKey []int32
	marked    []uint32 // second epoch, for the sweep back over shortest routes
	layer     []int32
	next      []int32

	// What the routes add up to.
	flow       []int64
	keyLength  []int16
	nodeLength []int16
	keep       []bool // SHORTEST: on a shortest route of some pair
	pairs      int
	rerouted   int // the cheapest route was refused and another one held
	dropped    int // every route of a pair was refused
}

func (pg *pairGraph) newSearcher() *pairSearcher {
	n, k := len(pg.nodes), len(pg.keys)
	w := &pairSearcher{
		pg:         pg,
		routes:     engine.NewRouteChecker(pg.s.aqlq.datasource),
		seen:       make([]uint32, n),
		dist:       make([]int16, n),
		best:       make([]float64, n),
		parent:     make([]int32, n),
		parentKey:  make([]int32, n),
		marked:     make([]uint32, n),
		flow:       make([]int64, k),
		keyLength:  make([]int16, k),
		nodeLength: make([]int16, n),
	}
	for i := range w.keyLength {
		w.keyLength[i] = -1
	}
	for i := range w.nodeLength {
		w.nodeLength[i] = -1
	}
	return w
}

// search finds the cheapest route from the seeds to every node within the
// depth limit over adjacency: fewest edges, then the most probable, then
// the parent of lowest rank, so the result does not depend on order.
func (w *pairSearcher) search(seeds []int32, adjacency [][]pairArc) {
	w.epoch++
	w.layer = w.layer[:0]
	for _, a := range seeds {
		w.seen[a], w.dist[a], w.best[a], w.parent[a], w.parentKey[a] = w.epoch, 0, 1, -1, -1
		w.layer = append(w.layer, a)
	}
	for d := int16(0); int(d) < w.pg.depth && len(w.layer) > 0; d++ {
		w.next = w.next[:0]
		for _, u := range w.layer {
			if d > 0 && !w.pg.passable[u] {
				continue
			}
			for _, arc := range adjacency[u] {
				v, p := arc.to, w.best[u]*arc.probability
				if w.seen[v] != w.epoch {
					w.seen[v], w.dist[v], w.best[v], w.parent[v], w.parentKey[v] = w.epoch, d+1, p, u, arc.key
					w.next = append(w.next, v)
				} else if w.dist[v] == d+1 && (p > w.best[v] || p == w.best[v] && w.pg.ranks[u] < w.pg.ranks[w.parent[v]]) {
					w.best[v], w.parent[v], w.parentKey[v] = p, u, arc.key
				}
			}
		}
		w.layer, w.next = w.next, w.layer
	}
}

func (w *pairSearcher) reached(v int32) bool {
	return w.seen[v] == w.epoch
}

// trace returns the route the search found to b, from the seed, as nodes
// and the edges between them.
func (w *pairSearcher) trace(b int32) ([]int32, []int32) {
	nodes := []int32{b}
	var keys []int32
	for v := b; w.parent[v] >= 0; v = w.parent[v] {
		nodes = append(nodes, w.parent[v])
		keys = append(keys, w.parentKey[v])
	}
	slices.Reverse(nodes)
	slices.Reverse(keys)
	return nodes, keys
}

// refused reports whether a deny refuses a step of a route, given along
// the edges, to the account acting there.
func (w *pairSearcher) refused(nodes, keys []int32) bool {
	var actor *engine.Node
	for i, key := range keys {
		from := w.pg.node(nodes[i])
		if engine.IsActor(from) {
			actor = from
		}
		eb := w.pg.types[key]
		if w.routes.Refused(actor, from, w.pg.node(nodes[i+1]), eb) == eb {
			return true
		}
	}
	return false
}

// unrefused finds the cheapest route along the edges from from to to that
// no deny refuses to the account acting at each step, searching states of
// a node and the account acting there.
func (w *pairSearcher) unrefused(from, to int32) ([]int32, []int32, bool) {
	type state struct{ node, actor int32 }
	type visit struct {
		dist   int
		best   float64
		parent state
		key    int32
	}
	none := state{-1, -1}
	actorAt := func(v, actor int32) int32 {
		if engine.IsActor(w.pg.node(v)) {
			return v
		}
		return actor
	}
	start := state{from, actorAt(from, -1)}
	visits := map[state]visit{start: {0, 1, none, -1}}
	layer := []state{start}
	var found []state
	for d := 0; d < w.pg.depth && len(layer) > 0 && len(found) == 0; d++ {
		var next []state
		for _, u := range layer {
			if d > 0 && !w.pg.passable[u.node] {
				continue
			}
			at := visits[u]
			var actor *engine.Node
			if u.actor >= 0 {
				actor = w.pg.node(u.actor)
			}
			for _, arc := range w.pg.along[u.node] {
				eb := w.pg.types[arc.key]
				if w.routes.Refused(actor, w.pg.node(u.node), w.pg.node(arc.to), eb) == eb {
					continue
				}
				v := state{arc.to, actorAt(arc.to, u.actor)}
				p := at.best * arc.probability
				if seen, ok := visits[v]; !ok {
					visits[v] = visit{d + 1, p, u, arc.key}
					next = append(next, v)
					if v.node == to {
						found = append(found, v)
					}
				} else if seen.dist == d+1 && (p > seen.best || p == seen.best && w.pg.ranks[u.node] < w.pg.ranks[seen.parent.node]) {
					visits[v] = visit{d + 1, p, u, arc.key}
				}
			}
		}
		layer = next
	}
	if len(found) == 0 {
		return nil, nil, false
	}
	end := found[0]
	for _, v := range found[1:] {
		a, b := visits[v], visits[end]
		if a.best > b.best || a.best == b.best && w.pg.ranks[a.parent.node] < w.pg.ranks[b.parent.node] {
			end = v
		}
	}
	nodes := []int32{end.node}
	var keys []int32
	for v := end; visits[v].parent != none; v = visits[v].parent {
		nodes = append(nodes, visits[v].parent.node)
		keys = append(keys, visits[v].key)
	}
	slices.Reverse(nodes)
	slices.Reverse(keys)
	return nodes, keys, true
}

// add counts a route, given along the edges.
func (w *pairSearcher) add(nodes, keys []int32) {
	length := int16(len(keys))
	w.pairs++
	for _, key := range keys {
		w.flow[key]++
		if w.keyLength[key] < 0 || length < w.keyLength[key] {
			w.keyLength[key] = length
		}
	}
	for _, v := range nodes {
		if w.nodeLength[v] < 0 || length < w.nodeLength[v] {
			w.nodeLength[v] = length
		}
	}
}

// cheapest keeps the cheapest route from the seeds to each node of other
// that no deny refuses. fromStarts says whether the seeds are start nodes;
// alongEdges whether the search runs with the edges.
func (w *pairSearcher) cheapest(seeds []int32, other []bool, adjacency [][]pairArc, alongEdges, zeroLength bool) {
	w.search(seeds, adjacency)
	for b, isOther := range other {
		b := int32(b)
		if !isOther || !w.reached(b) {
			continue
		}
		nodes, keys := w.trace(b)
		if len(keys) == 0 {
			if zeroLength {
				w.add(nodes, nil)
			}
			continue
		}
		if !alongEdges {
			slices.Reverse(nodes)
			slices.Reverse(keys)
		}
		if w.refused(nodes, keys) {
			var ok bool
			if nodes, keys, ok = w.unrefused(nodes[0], nodes[len(nodes)-1]); !ok {
				w.dropped++
				continue
			}
			w.rerouted++
		}
		w.add(nodes, keys)
	}
}

// shortest marks the edges on every shortest route from the seeds to a
// node of other, sweeping back from those nodes over edges one shorter.
func (w *pairSearcher) shortest(seeds []int32, other []bool, adjacency, reverse [][]pairArc, zeroLength bool) {
	w.search(seeds, adjacency)
	queue := w.next[:0]
	for b, isOther := range other {
		if isOther && w.reached(int32(b)) && (w.dist[b] > 0 || zeroLength) {
			w.marked[b] = w.epoch
			queue = append(queue, int32(b))
			w.pairs++
			if w.nodeLength[b] < 0 || w.dist[b] < w.nodeLength[b] {
				w.nodeLength[b] = w.dist[b]
			}
		}
	}
	for len(queue) > 0 {
		v := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		for _, arc := range reverse[v] {
			u := arc.to
			if !w.reached(u) || w.dist[u] != w.dist[v]-1 || w.dist[u] > 0 && !w.pg.passable[u] {
				continue
			}
			w.keep[arc.key] = true
			if w.marked[u] != w.epoch {
				w.marked[u] = w.epoch
				queue = append(queue, u)
			}
		}
	}
	w.next = queue
}

// pairRoutes keeps the routes the query's REACH ROUTES mode asks for: the
// cheapest route from each start to each end (CHEAPEST), or every shortest
// one (SHORTEST). It returns a note when there were too many pairs to
// search one by one.
func (s *reachSearch) pairRoutes(edges map[reachKey]reachResultEdge, nodeLength map[engine.NodeIndex]int) (string, error) {
	pg := s.newPairGraph(edges, nodeLength)
	isStart := make([]bool, len(pg.nodes))
	isEnd := make([]bool, len(pg.nodes))
	var starts, ends []int32
	for i := range pg.nodes {
		node := pg.node(int32(i))
		if s.aqlq.sourceCache[0].Contains(node) {
			isStart[i] = true
			starts = append(starts, int32(i))
		}
		if s.aqlq.sourceCache[1].Contains(node) {
			isEnd[i] = true
			ends = append(ends, int32(i))
		}
	}
	// Search from the smaller side.
	seeds, other, adjacency, reverse := starts, isEnd, pg.search, pg.against
	fromStarts := true
	if len(ends) < len(starts) {
		seeds, other, adjacency, reverse = ends, isStart, pg.against, pg.search
		fromStarts = false
	}
	alongEdges := fromStarts == (s.aqlq.Next[0].Direction == engine.Out)
	zeroLength := s.aqlq.Next[0].MinIterations == 0

	var note string
	together := len(seeds)*(len(pg.keys)+len(pg.nodes)) > reachPairWork
	if together {
		sides := [2]string{"start", "end"}
		if !fromStarts {
			sides[0], sides[1] = sides[1], sides[0]
		}
		note = fmt.Sprintf("Too many pairs of %v %v and %v %v nodes to search each: kept routes to each %v node from the nearest %v node", len(seeds), sides[0], len(other), sides[1], sides[1], sides[0])
	}

	workers := min(runtime.NumCPU(), 8, max(len(seeds), 1))
	if together {
		workers = 1
	}
	searchers := make([]*pairSearcher, workers)
	jobs := make(chan int32)
	var wg sync.WaitGroup
	var firstErr error
	var errOnce sync.Once
	for i := range searchers {
		w := pg.newSearcher()
		if s.aqlq.Routes == RoutesShortest {
			w.keep = make([]bool, len(pg.keys))
		}
		searchers[i] = w
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range jobs {
				if err := s.opts.cancelled(); err != nil {
					errOnce.Do(func() { firstErr = err })
					continue
				}
				group := []int32{a}
				if together {
					group = seeds
				}
				if s.aqlq.Routes == RoutesShortest {
					w.shortest(group, other, adjacency, reverse, zeroLength)
				} else {
					w.cheapest(group, other, adjacency, alongEdges, zeroLength)
				}
			}
		}()
	}
	if together {
		jobs <- -1
	} else {
		for _, a := range seeds {
			jobs <- a
		}
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return "", firstErr
	}

	// Merge what the workers found.
	flow := make([]int64, len(pg.keys))
	keyLength := make([]int16, len(pg.keys))
	keep := make([]bool, len(pg.keys))
	nodeLen := make([]int16, len(pg.nodes))
	for i := range keyLength {
		keyLength[i] = -1
	}
	for i := range nodeLen {
		nodeLen[i] = -1
	}
	pairs, rerouted, refused := 0, 0, 0
	for _, w := range searchers {
		pairs, rerouted, refused = pairs+w.pairs, rerouted+w.rerouted, refused+w.dropped
		for i := range flow {
			flow[i] += w.flow[i]
			if l := w.keyLength[i]; l >= 0 && (keyLength[i] < 0 || l < keyLength[i]) {
				keyLength[i] = l
			}
			if w.keep != nil && w.keep[i] {
				keep[i] = true
			}
		}
		for i, l := range w.nodeLength {
			if l >= 0 && (nodeLen[i] < 0 || l < nodeLen[i]) {
				nodeLen[i] = l
			}
		}
	}

	if s.aqlq.Routes == RoutesShortest {
		// The nodes on kept edges, with the length the flow count works out
		// again.
		for i, key := range pg.keys {
			if !keep[i] {
				delete(edges, key)
			}
		}
		kept := map[engine.NodeIndex]bool{}
		for key := range edges {
			kept[key.from], kept[key.to] = true, true
		}
		for i, l := range nodeLen {
			if l == 0 {
				kept[pg.nodes[i]] = true
			}
		}
		for v := range nodeLength {
			if !kept[v] {
				delete(nodeLength, v)
			}
		}
		if err := s.countFlows(edges, nodeLength); err != nil {
			return "", err
		}
		return note, nil
	}

	clear(edges)
	for i, key := range pg.keys {
		if flow[i] > 0 {
			edges[key] = reachResultEdge{edges: pg.types[i], length: int(keyLength[i]), flow: int(min(flow[i], 1<<31-1))}
		}
	}
	clear(nodeLength)
	for i, l := range nodeLen {
		if l >= 0 {
			nodeLength[pg.nodes[i]] = int(l)
		}
	}
	if rerouted > 0 || refused > 0 {
		ui.Info().Msgf("REACH CHEAPEST: denies refused the cheapest route of %v of %v pairs: %v took another route, %v had none", rerouted+refused, pairs+refused, rerouted, refused)
	}
	return note, nil
}
