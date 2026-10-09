package aql

import (
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/ui"
)

// countFlows sets each edge's flow to the number of routes through it that
// no deny refuses, and removes what lies on no such route.
//
// An edge from a group stands for every member, but a deny for a member, or
// for another group the member is in, refuses it to that member alone. REACH
// keeps edges, not routes, so the result is searched again, counting routes
// by length over states of a node and the account a route acts as there:
// entering an account makes it the one acting, and groups and other objects
// keep the account before them. Only accounts some deny refuses get states
// of their own; every other account shares one, so without such a deny the
// count is over nodes alone.
//
// Recombining the result's edges is only exact for a single step with no
// path node filter and a single direction; other queries keep a flow of 1.
func (s *reachSearch) countFlows(edges map[reachKey]reachResultEdge, nodeLength map[engine.NodeIndex]int) error {
	if !s.recombinable() {
		return nil
	}
	step := s.aqlq.Next[0]
	depth := min(s.maxDepth, max(step.MaxIterations, 1))
	ds := s.aqlq.datasource

	keys := make([]reachKey, 0, len(edges))
	for key := range edges {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b reachKey) int {
		if a.from != b.from {
			return int(a.from) - int(b.from)
		}
		return int(a.to) - int(b.to)
	})
	out := map[engine.NodeIndex][]int{} // node -> positions in keys
	in := map[engine.NodeIndex][]int{}
	types := make([]engine.EdgeBitmap, len(keys))
	for i, key := range keys {
		out[key.from] = append(out[key.from], i)
		in[key.to] = append(in[key.to], i)
		types[i] = edges[key].edges
	}
	isAccount := func(v engine.NodeIndex) bool {
		return engine.IsActor(ds.NodeAt(v))
	}

	// The nearest accounts before a node on the result's routes.
	nearest := map[engine.NodeIndex][]engine.NodeIndex{}
	accountsBefore := func(from engine.NodeIndex) []engine.NodeIndex {
		if isAccount(from) {
			return []engine.NodeIndex{from}
		}
		if found, done := nearest[from]; done {
			return found
		}
		var accounts []engine.NodeIndex
		seen := map[engine.NodeIndex]bool{from: true}
		queue := []engine.NodeIndex{from}
		for len(queue) > 0 {
			v := queue[0]
			queue = queue[1:]
			for _, i := range in[v] {
				p := keys[i].from
				if seen[p] {
					continue
				}
				seen[p] = true
				if isAccount(p) {
					accounts = append(accounts, p)
				} else {
					queue = append(queue, p)
				}
			}
		}
		nearest[from] = accounts
		return accounts
	}

	// Which accounts are refused which edges. Edges from one node with the
	// same denies refuse the same accounts, which is common: inherited
	// denies repeat on every object below where they are set.
	type refusalKey struct {
		edge  int // position in keys
		actor engine.NodeIndex
	}
	refusals := map[refusalKey]engine.EdgeBitmap{}
	relevant := map[engine.NodeIndex]int{} // account -> its own actor number
	var actors []engine.NodeIndex
	type refused struct {
		actor engine.NodeIndex
		edges engine.EdgeBitmap
	}
	bySignature := map[string][]refused{}
	checkers := engine.NewActorCheckers(ds)
	for i, key := range keys {
		from, to := ds.NodeAt(key.from), ds.NodeAt(key.to)
		for ci, c := range checkers {
			found := c.Refusers(from, to, edges[key].edges)
			if len(found) == 0 {
				continue
			}
			if err := s.opts.cancelled(); err != nil {
				return err
			}
			signature := refusalSignature(ci, key.from, found)
			list, done := bySignature[signature]
			if !done {
				// Only accounts holding one of the refusing SIDs can be
				// refused; most accounts before a group hold none.
				holders := map[engine.NodeIndex]bool{}
				for _, r := range found {
					for _, grant := range r.Grants {
						for _, sid := range grant {
							for _, h := range c.Holders(sid, to) {
								if v, found := ds.NodeIndexOf(h); found {
									holders[v] = true
								}
							}
						}
					}
				}
				for _, actor := range accountsBefore(key.from) {
					if !holders[actor] {
						continue
					}
					inToken := c.InToken(ds.NodeAt(actor))
					var eb engine.EdgeBitmap
					for _, r := range found {
						if r.RefusedTo(inToken) {
							eb = eb.Set(r.Edge)
						}
					}
					if !eb.IsBlank() {
						list = append(list, refused{actor, eb})
					}
				}
				bySignature[signature] = list
			}
			for _, r := range list {
				refusals[refusalKey{i, r.actor}] = refusals[refusalKey{i, r.actor}].Merge(r.edges)
				if _, found := relevant[r.actor]; !found {
					actors = append(actors, r.actor)
					relevant[r.actor] = len(actors)
				}
			}
		}
	}

	// An account needs states of its own only where a route acting as it
	// can still reach an edge it is refused: from the edge's source back
	// through nodes that are not accounts, as entering an account changes
	// who acts. Elsewhere it shares the state of every other account.
	// The refusals of each edge, by actor number.
	type actorRefusal struct {
		actor int
		edges engine.EdgeBitmap
	}
	refusedOn := make([][]actorRefusal, len(keys))
	for key, eb := range refusals {
		refusedOn[key.edge] = append(refusedOn[key.edge], actorRefusal{relevant[key.actor], eb})
	}

	region := make([]map[engine.NodeIndex]bool, len(actors)+1)
	for key := range refusals {
		a := relevant[key.actor]
		if region[a] == nil {
			region[a] = map[engine.NodeIndex]bool{}
		}
		start := keys[key.edge].from
		if region[a][start] {
			continue
		}
		region[a][start] = true
		queue := []engine.NodeIndex{start}
		for len(queue) > 0 {
			v := queue[0]
			queue = queue[1:]
			if isAccount(v) {
				continue // entering v makes it the one acting
			}
			for _, i := range in[v] {
				if p := keys[i].from; !region[a][p] {
					region[a][p] = true
					queue = append(queue, p)
				}
			}
		}
	}

	// Routes run from the attacker's end: the end nodes when the query
	// walks edges backwards from its start, the start nodes otherwise.
	var attackers, targets []engine.NodeIndex
	for _, v := range s.active[0] {
		if _, found := nodeLength[v]; found && s.forward[v] == 0 {
			targets = append(targets, v)
		}
	}
	for _, v := range s.active[len(s.layerStep)-1] {
		if _, found := nodeLength[v]; found {
			attackers = append(attackers, v)
		}
	}
	if step.Direction == engine.Out {
		attackers, targets = targets, attackers
	}
	isTarget := map[engine.NodeIndex]bool{}
	for _, v := range targets {
		isTarget[v] = true
	}

	passable := s.passable

	// States are numbered as they are reached; per state, the routes of
	// each length from an attacker (forward) and to a target (backward).
	type state struct {
		node  engine.NodeIndex
		actor int // 0 for every account no deny refuses, or none yet
	}
	type move struct {
		to    int32 // state
		edge  int   // position in keys
		edges engine.EdgeBitmap
	}
	width := depth + 1
	var (
		states   []state
		number   = map[state]int32{}
		forward  []float64
		moves    [][]move
		expanded []bool
	)
	// States of the shared actor are numbered by node, the few others by
	// a map.
	shared := make([]int32, ds.Order())
	for i := range shared {
		shared[i] = -1
	}
	stateOf := func(st state) int32 {
		if st.actor == 0 {
			if n := shared[st.node]; n >= 0 {
				return n
			}
		} else if n, found := number[st]; found {
			return n
		}
		n := int32(len(states))
		if st.actor == 0 {
			shared[st.node] = n
		} else {
			number[st] = n
		}
		states = append(states, st)
		forward = append(forward, make([]float64, width)...)
		moves = append(moves, nil)
		expanded = append(expanded, false)
		return n
	}
	actorAt := func(v engine.NodeIndex, current int) int {
		if isAccount(v) {
			current = relevant[v]
		}
		if current > 0 && !region[current][v] {
			return 0
		}
		return current
	}
	expand := func(n int32) []move {
		if expanded[n] {
			return moves[n]
		}
		st := states[n]
		var result []move
		for _, i := range out[st.node] {
			eb := types[i]
			if st.actor > 0 {
				for _, r := range refusedOn[i] {
					if r.actor == st.actor {
						for _, edge := range r.edges.Edges() {
							eb = eb.Clear(edge)
						}
					}
				}
			}
			if !eb.IsBlank() {
				result = append(result, move{stateOf(state{keys[i].to, actorAt(keys[i].to, st.actor)}), i, eb})
			}
		}
		moves[n], expanded[n] = result, true
		return result
	}

	// mark[n] == epoch when state n is already in the next frontier.
	var mark []int32
	epoch := int32(0)
	marked := func(n int32) bool {
		for int(n) >= len(mark) {
			mark = append(mark, -1)
		}
		if mark[n] == epoch {
			return true
		}
		mark[n] = epoch
		return false
	}
	var frontier []int32
	for _, v := range attackers {
		n := stateOf(state{v, actorAt(v, 0)})
		forward[int(n)*width] = 1
		if !marked(n) {
			frontier = append(frontier, n)
		}
	}
	for l := 0; l < depth && len(frontier) > 0; l++ {
		if err := s.opts.cancelled(); err != nil {
			return err
		}
		var next []int32
		epoch++
		for _, n := range frontier {
			if l > 0 && !passable(states[n].node) {
				continue
			}
			count := forward[int(n)*width+l]
			for _, m := range expand(n) {
				forward[int(m.to)*width+l+1] += count
				if !marked(m.to) {
					next = append(next, m.to)
				}
			}
		}
		frontier = next
	}

	reverse := make([][]int32, len(states))
	for n := range states {
		for _, m := range moves[n] {
			reverse[m.to] = append(reverse[m.to], int32(n))
		}
	}
	backward := make([]float64, len(states)*width)
	frontier = frontier[:0]
	epoch++
	for n, st := range states {
		if isTarget[st.node] {
			backward[n*width] = 1
			frontier = append(frontier, int32(n))
		}
	}
	for l := 0; l < depth && len(frontier) > 0; l++ {
		if err := s.opts.cancelled(); err != nil {
			return err
		}
		var next []int32
		epoch++
		for _, n := range frontier {
			if l > 0 && !passable(states[n].node) {
				continue
			}
			count := backward[int(n)*width+l]
			for _, p := range reverse[n] {
				backward[int(p)*width+l+1] += count
				if !marked(p) {
					next = append(next, p)
				}
			}
		}
		frontier = next
	}

	// The routes through a move are those of l1 edges to it and l2 from it
	// with l1+1+l2 within the depth.
	shortest := func(counts []float64) int {
		for l, c := range counts {
			if c > 0 {
				return l
			}
		}
		return -1
	}
	upTo := make([]float64, len(states)*width) // backward routes of up to l edges
	for n := range states {
		var sum float64
		for l := range width {
			sum += backward[n*width+l]
			upTo[n*width+l] = sum
		}
	}
	type flowEdge struct {
		edges  engine.EdgeBitmap
		flow   float64
		length int
	}
	kept := map[int]flowEdge{}
	for n := range states {
		f := forward[n*width : (n+1)*width]
		before := shortest(f)
		if before < 0 {
			continue
		}
		for _, m := range moves[n] {
			after := upTo[int(m.to)*width : (int(m.to)+1)*width]
			var routes float64
			for l1, c := range f[:depth] {
				if c > 0 && (l1 == 0 || passable(states[n].node)) {
					if passable(states[m.to].node) {
						routes += c * after[depth-1-l1]
					} else {
						routes += c * backward[int(m.to)*width] // m.to ends the route
					}
				}
			}
			if routes == 0 {
				continue
			}
			length := before + 1 + shortest(backward[int(m.to)*width:(int(m.to)+1)*width])
			fe, found := kept[m.edge]
			if !found || length < fe.length {
				fe.length = length
			}
			fe.edges = fe.edges.Merge(m.edges)
			fe.flow += routes
			kept[m.edge] = fe
		}
	}
	lengths := map[engine.NodeIndex]int{}
	for n, st := range states {
		before := shortest(forward[n*width : (n+1)*width])
		after := shortest(backward[n*width : (n+1)*width])
		if !passable(st.node) && before > 0 && after > 0 {
			// A route may only start or end here.
			switch {
			case forward[n*width] > 0:
				before = 0
			case backward[n*width] > 0:
				after = 0
			default:
				continue
			}
		}
		if before < 0 || after < 0 || before+after > depth {
			continue
		}
		if l, found := lengths[st.node]; !found || before+after < l {
			lengths[st.node] = before + after
		}
	}

	if removed := len(edges) - len(kept); removed > 0 || len(nodeLength) > len(lengths) {
		ui.Info().Msgf("REACH: denies refuse %v edges and %v nodes to every account that would use them", removed, len(nodeLength)-len(lengths))
	}
	clear(edges)
	for i, fe := range kept {
		edges[keys[i]] = reachResultEdge{edges: fe.edges, length: fe.length, flow: int(min(fe.flow, math.MaxInt32))}
	}
	clear(nodeLength)
	for v, l := range lengths {
		nodeLength[v] = l
	}
	return nil
}

// refusalSignature identifies a checker's refusals of the edges from one
// node, so edges refusing the same accounts are worked out once.
func refusalSignature(checker int, from engine.NodeIndex, refusals []engine.Refusal) string {
	var b strings.Builder
	b.WriteString(strconv.Itoa(checker))
	b.WriteByte('/')
	b.WriteString(strconv.Itoa(int(from)))
	sorted := slices.Clone(refusals)
	slices.SortFunc(sorted, func(a, b engine.Refusal) int { return int(a.Edge) - int(b.Edge) })
	for _, r := range sorted {
		b.WriteByte('|')
		b.WriteString(strconv.Itoa(int(r.Edge)))
		for _, grant := range r.Grants {
			b.WriteByte(':')
			sids := slices.Clone(grant)
			slices.Sort(sids)
			for _, sid := range slices.Compact(sids) {
				b.WriteString(string(sid))
				b.WriteByte(',')
			}
		}
	}
	return b.String()
}
